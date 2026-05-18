//! Websocket monitoring feed built on `fastwebsockets`.
//!
//! Each client receives an immediate snapshot on connect, then every
//! [`MonitorEvent`] broadcast by the manager (a fresh snapshot once a second).

use crate::manager::Manager;
use crate::model::now_ms;
use crate::monitor::MonitorEvent;
use fastwebsockets::upgrade::UpgradeFut;
use fastwebsockets::{Frame, Payload, WebSocket, WebSocketError};
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

/// Serialize an event to JSON and write it as a text frame.
async fn send<S>(ws: &mut WebSocket<S>, event: &MonitorEvent) -> Result<(), WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());
    ws.write_frame(Frame::text(Payload::Owned(json.into_bytes())))
        .await
}
