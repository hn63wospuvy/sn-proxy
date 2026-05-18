//! Plain TCP forwarder: every connection accepted on the listen port is
//! relayed to a fixed `forward_to` destination configured on the proxy.

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use anyhow::{Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Handle one accepted connection for a TCP-forwarder proxy.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let (dst, connect_timeout, keepalive, idle) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.forward_to.clone(),
            cfg.connect_timeout_secs,
            cfg.keepalive_secs,
            cfg.idle_timeout_secs,
        )
    };
    let dst = match dst {
        Some(d) if !d.is_empty() => d,
        _ => bail!("tcp proxy has no forward destination configured"),
    };

    let target = match relay::connect(&dst, connect_timeout, keepalive).await {
        Ok(t) => t,
        Err(e) => bail!("connect to {dst} failed: {e}"),
    };

    relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
        let idle_fut =
            relay::idle_watchdog(entry.clone(), idle.filter(|s| *s > 0).map(Duration::from_secs));
        let mut client = relay::Counting::new(stream, entry);
        let mut target = target;
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut target) => {}
            _ = token.cancelled() => {}
            _ = idle_fut => {}
        }
    })
    .await;
    Ok(())
}
