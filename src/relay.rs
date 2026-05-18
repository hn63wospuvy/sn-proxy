//! Shared connection bookkeeping and a byte-counting stream wrapper used by
//! every proxy protocol.

use crate::manager::{ConnEntry, ProxyRuntime};
use crate::model::{ConnectionRecord, now_ms};
use crate::storage::Storage;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use uuid::Uuid;

/// Apply a TCP keep-alive interval to a socket (no-op when `secs` is 0/`None`).
pub fn apply_keepalive(stream: &TcpStream, secs: Option<u64>) {
    if let Some(s) = secs.filter(|s| *s > 0) {
        let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(s));
        let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
    }
}

/// Connect to `addr` honouring an optional connect timeout, then apply the
/// keep-alive setting to the resulting socket.
pub async fn connect(
    addr: &str,
    connect_timeout: Option<u64>,
    keepalive: Option<u64>,
) -> std::io::Result<TcpStream> {
    let stream = match connect_timeout.filter(|s| *s > 0) {
        Some(s) => tokio::time::timeout(Duration::from_secs(s), TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??,
        None => TcpStream::connect(addr).await?,
    };
    apply_keepalive(&stream, keepalive);
    Ok(stream)
}

/// Resolves once the connection has transferred no bytes for `idle`.
/// When `idle` is `None` it never resolves (idle timeout disabled).
pub async fn idle_watchdog(entry: Arc<ConnEntry>, idle: Option<Duration>) {
    let Some(d) = idle else {
        std::future::pending::<()>().await;
        return;
    };
    let mut last = 0u64;
    loop {
        tokio::time::sleep(d).await;
        let total = entry.bytes_sent.load(Ordering::Relaxed)
            + entry.bytes_received.load(Ordering::Relaxed);
        if total == last {
            return;
        }
        last = total;
    }
}

/// Register a connection for monitoring, run `relay`, then unregister it and
/// persist a history record.
///
/// The `relay` closure receives the live [`ConnEntry`] and is responsible for
/// updating its `bytes_sent` / `bytes_received` counters as it transfers data.
pub async fn tracked<F, Fut>(
    storage: &Arc<Storage>,
    runtime: &Arc<ProxyRuntime>,
    src_addr: String,
    dst_addr: String,
    relay: F,
) where
    F: FnOnce(Arc<ConnEntry>) -> Fut,
    Fut: Future<Output = ()>,
{
    let conn_id = Uuid::new_v4().to_string();
    let entry = Arc::new(ConnEntry {
        id: conn_id.clone(),
        src_addr: src_addr.clone(),
        dst_addr: dst_addr.clone(),
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        started_at: now_ms(),
    });
    runtime.conns.insert(conn_id.clone(), entry.clone());
    runtime.total_connections.fetch_add(1, Ordering::Relaxed);
    let proxy_id = runtime.config.lock().unwrap().id.clone();

    relay(entry.clone()).await;

    runtime.conns.remove(&conn_id);
    let sent = entry.bytes_sent.load(Ordering::Relaxed);
    let received = entry.bytes_received.load(Ordering::Relaxed);
    runtime.total_sent.fetch_add(sent, Ordering::Relaxed);
    runtime.total_received.fetch_add(received, Ordering::Relaxed);

    let record = ConnectionRecord {
        id: conn_id,
        proxy_id,
        src_addr,
        dst_addr,
        bytes_sent: sent,
        bytes_received: received,
        started_at: entry.started_at,
        closed_at: Some(now_ms()),
    };
    if let Err(e) = storage.save_history(&record) {
        tracing::warn!("save history failed: {e}");
    }
}

/// Stream wrapper that tallies transferred bytes onto a [`ConnEntry`].
///
/// Wrap the *client* side of a relay: bytes read from the client count as
/// "sent" (client -> destination), bytes written to it count as "received".
pub struct Counting<S> {
    inner: S,
    entry: Arc<ConnEntry>,
}

impl<S> Counting<S> {
    pub fn new(inner: S, entry: Arc<ConnEntry>) -> Self {
        Self { inner, entry }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = (buf.filled().len() - before) as u64;
            self.entry.bytes_sent.fetch_add(n, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            self.entry
                .bytes_received
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
