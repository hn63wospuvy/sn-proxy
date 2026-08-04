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
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Maximum time a client may take to complete a protocol handshake (SOCKS5
/// negotiation, HTTP/WebSocket request head, Shadowsocks salt + address header,
/// or the HTTPS listener's TLS handshake) before the connection is dropped.
/// Bounds slow-loris-style holds on the pre-relay phase, which the per-relay
/// idle watchdog does not cover (it only arms once relaying starts).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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

/// An upstream connection: a plain TCP socket, or one wrapped in client TLS
/// (used by HTTP/HTTPS proxies reaching `https://` destinations).
pub enum Upstream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// The host portion of a `host:port` (or `[ipv6]:port`) address.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(i) = rest.find(']') {
            return &rest[..i];
        }
    }
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}

/// Connect to `addr`, optionally wrapping the socket in a client-TLS session.
pub async fn connect_upstream(
    addr: &str,
    connect_timeout: Option<u64>,
    keepalive: Option<u64>,
    tls: Option<&TlsConnector>,
) -> std::io::Result<Upstream> {
    let tcp = connect(addr, connect_timeout, keepalive).await?;
    match tls {
        None => Ok(Upstream::Plain(tcp)),
        Some(connector) => {
            let host = host_of(addr).to_string();
            let name = ServerName::try_from(host.clone()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid TLS server name {host:?}: {e}"),
                )
            })?;
            let stream = connector.connect(name, tcp).await?;
            Ok(Upstream::Tls(Box::new(stream)))
        }
    }
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_write(cx, data),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_flush(cx),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
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
/// The relay is aborted if the connection's [`ConnEntry::cancel`] token fires,
/// which is how the admin "terminate connection" / "block IP" actions work.
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
        cancel: CancellationToken::new(),
    });
    runtime.conns.insert(conn_id.clone(), entry.clone());
    runtime.total_connections.fetch_add(1, Ordering::Relaxed);
    let proxy_id = runtime.config.lock().unwrap().id.clone();

    let cancel = entry.cancel.clone();
    tokio::select! {
        _ = relay(entry.clone()) => {}
        _ = cancel.cancelled() => {}
    }

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

/// Register a UDP session for monitoring: build a fresh [`ConnEntry`], insert
/// it into `runtime.conns` and bump the connection counter. Mirrors the setup
/// half of [`tracked`]. The returned entry's `cancel` token drives teardown.
pub fn udp_session_start(
    runtime: &Arc<ProxyRuntime>,
    src: String,
    dst: String,
) -> Arc<ConnEntry> {
    let conn_id = Uuid::new_v4().to_string();
    let entry = Arc::new(ConnEntry {
        id: conn_id.clone(),
        src_addr: src,
        dst_addr: dst,
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        started_at: now_ms(),
        cancel: CancellationToken::new(),
    });
    runtime.conns.insert(conn_id, entry.clone());
    runtime.total_connections.fetch_add(1, Ordering::Relaxed);
    entry
}

/// Tear down a UDP session: remove it from `runtime.conns`, fold its byte
/// counters into the proxy totals and persist one history record. Mirrors the
/// teardown half of [`tracked`]. MUST be called exactly once per session.
pub fn udp_session_end(
    storage: &Arc<Storage>,
    runtime: &Arc<ProxyRuntime>,
    entry: &Arc<ConnEntry>,
) {
    runtime.conns.remove(&entry.id);
    let sent = entry.bytes_sent.load(Ordering::Relaxed);
    let received = entry.bytes_received.load(Ordering::Relaxed);
    runtime.total_sent.fetch_add(sent, Ordering::Relaxed);
    runtime.total_received.fetch_add(received, Ordering::Relaxed);
    let proxy_id = runtime.config.lock().unwrap().id.clone();
    let record = ConnectionRecord {
        id: entry.id.clone(),
        proxy_id,
        src_addr: entry.src_addr.clone(),
        dst_addr: entry.dst_addr.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::ProxyRuntime;
    use crate::model::{Protocol, ProxyConfig};
    use crate::storage::Storage;

    fn runtime() -> Arc<ProxyRuntime> {
        let cfg = ProxyConfig {
            id: "px1".into(),
            name: "n".into(),
            protocol: Protocol::Udp,
            listen_addr: "0.0.0.0:0".into(),
            auth: None,
            ss_method: None,
            ss_password: None,
            send_proxy_protocol: false,
            forward_to: Some("1.2.3.4:53".into()),
            keepalive_secs: None,
            idle_timeout_secs: None,
            connect_timeout_secs: None,
            client_p12: None,
            client_p12_password: None,
            client_p12_alias: None,
            client_p12_entry_password: None,
            override_headers: Vec::new(),
            server_p12: None,
            server_p12_password: None,
            server_truststore_p12: None,
            server_truststore_password: None,
            mtls_required: false,
            blocklist: Vec::new(),
            max_connections: None,
            udp_associate_enabled: true,
            udp_allow_private: false,
            udp_bind_addr: None,
            udp_advertise_ip: None,
            udp_max_datagram: None,
            udp_max_dests: None,
            turn: crate::model::TurnConfig::default(),
            enabled: false,
        };
        Arc::new(ProxyRuntime::new(cfg))
    }

    fn storage() -> Arc<Storage> {
        let dir = std::env::temp_dir().join(format!("snproxy-relay-{}", Uuid::new_v4()));
        Storage::open(dir.to_str().unwrap()).unwrap()
    }

    #[test]
    fn session_start_registers_conn() {
        let rt = runtime();
        let entry = udp_session_start(&rt, "5.5.5.5:40000".into(), "1.2.3.4:53".into());
        assert_eq!(entry.src_addr, "5.5.5.5:40000");
        assert_eq!(entry.dst_addr, "1.2.3.4:53");
        assert_eq!(rt.conns.len(), 1);
        assert_eq!(rt.total_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn session_end_folds_totals_and_removes() {
        let rt = runtime();
        let st = storage();
        let entry = udp_session_start(&rt, "5.5.5.5:40000".into(), "1.2.3.4:53".into());
        entry.bytes_sent.store(100, Ordering::Relaxed);
        entry.bytes_received.store(40, Ordering::Relaxed);
        udp_session_end(&st, &rt, &entry);
        assert_eq!(rt.conns.len(), 0);
        assert_eq!(rt.total_sent.load(Ordering::Relaxed), 100);
        assert_eq!(rt.total_received.load(Ordering::Relaxed), 40);
        let recs = st.load_history("px1", 0, 10).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].proxy_id, "px1");
        assert_eq!(recs[0].bytes_sent, 100);
        assert!(recs[0].closed_at.is_some());
    }
}
