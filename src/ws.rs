//! Websocket monitoring feed built on `fastwebsockets`.
//!
//! Each client receives an immediate snapshot on connect, then every
//! [`MonitorEvent`] broadcast by the manager (a fresh snapshot once a second).

use crate::manager::Manager;
use crate::model::now_ms;
use crate::monitor::MonitorEvent;
use fastwebsockets::upgrade::UpgradeFut;
use fastwebsockets::{Frame, Payload, WebSocket, WebSocketError};
use serde::Serialize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast::error::RecvError;

/// Drive a websocket connection: push snapshots until the client goes away.
pub async fn handle(fut: UpgradeFut, manager: Arc<Manager>) -> Result<(), WebSocketError> {
    let mut ws = fut.await?;
    let mut rx = manager.events.subscribe();

    // Send the current state straight away so the UI is not blank.
    let initial = MonitorEvent::Snapshot {
        ts: now_ms(),
        proxies: manager.snapshot(),
    };
    send(&mut ws, &initial).await?;

    loop {
        match rx.recv().await {
            Ok(event) => send(&mut ws, &event).await?,
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// Drive a host-resource websocket: push each [`ResourceSample`] as it is
/// broadcast. Subscribing here is what turns the demand-driven collector on, so
/// the first sample arrives on the next 1-second tick (no immediate snapshot).
pub async fn handle_resources(fut: UpgradeFut, manager: Arc<Manager>) -> Result<(), WebSocketError> {
    let mut ws = fut.await?;
    let mut rx = manager.resource_events.subscribe();
    loop {
        match rx.recv().await {
            Ok(sample) => send(&mut ws, &sample).await?,
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// Serialize a payload to JSON and write it as a text frame. Serialization never
/// panics: on the (practically impossible) error it falls back to `{}`.
async fn send<S, T>(ws: &mut WebSocket<S>, payload: &T) -> Result<(), WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    ws.write_frame(Frame::text(Payload::Owned(json.into_bytes())))
        .await
}
