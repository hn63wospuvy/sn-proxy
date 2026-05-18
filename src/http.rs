//! HTTP proxy: `CONNECT` tunnelling and plain HTTP forwarding, with optional
//! Basic authentication.
//!
//! The handler is generic over the client stream, so it serves both the plain
//! `http` protocol (over `TcpStream`) and the TLS-wrapped `https` protocol
//! (over a `TlsStream`).

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use anyhow::{Result, bail};
use base64::Engine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const MAX_HEADER: usize = 64 * 1024;

/// Handle a single accepted HTTP(S) proxy client connection.
pub async fn serve<S>(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: S,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Read the request head (everything up to the blank line).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER {
            let _ = stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await;
            bail!("request header too large");
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("client closed before sending a request");
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    // Optional Basic authentication.
    let configured_auth = runtime.config.lock().unwrap().auth.clone();
    if let Some(auth) = configured_auth {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        let expected = format!("Basic {creds}");
        let provided = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, v)| v.as_str());
        if provided != Some(expected.as_str()) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"sn-proxy\"\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            bail!("http proxy authentication failed");
        }
    }

    let (connect_timeout, keepalive, idle) = {
        let cfg = runtime.config.lock().unwrap();
        (cfg.connect_timeout_secs, cfg.keepalive_secs, cfg.idle_timeout_secs)
    };

    // Bytes received after the header block — pipelined body / TLS data.
    let extra: Vec<u8> = buf.split_off((head_end + 4).min(buf.len()));

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT <host:port> — open a raw tunnel.
        let dst = target;
        let mut upstream = match relay::connect(&dst, connect_timeout, keepalive).await {
            Ok(u) => u,
            Err(e) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                bail!("connect to {dst} failed: {e}");
            }
        };
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !extra.is_empty() {
            upstream.write_all(&extra).await?;
        }
        relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
            let idle_fut = relay::idle_watchdog(
                entry.clone(),
                idle.filter(|s| *s > 0).map(Duration::from_secs),
            );
            let mut client = relay::Counting::new(stream, entry);
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                _ = token.cancelled() => {}
                _ = idle_fut => {}
            }
        })
        .await;
    } else {
        // Plain forwarding — the target is an absolute-form URI.
        let (host, port, path) = parse_absolute_uri(&target)?;
        let dst = format!("{host}:{port}");
        let mut upstream = match relay::connect(&dst, connect_timeout, keepalive).await {
            Ok(u) => u,
            Err(e) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                bail!("connect to {dst} failed: {e}");
            }
        };
        // Rebuild the request in origin-form, dropping proxy/hop-by-hop headers.
        let mut out = format!("{method} {path} {version}\r\n");
        let mut has_host = false;
        for (k, v) in &headers {
            let lk = k.to_ascii_lowercase();
            if lk == "proxy-authorization" || lk == "proxy-connection" || lk == "connection" {
                continue;
            }
            if lk == "host" {
                has_host = true;
            }
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        if !has_host {
            out.push_str(&format!("Host: {host}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        upstream.write_all(out.as_bytes()).await?;
        if !extra.is_empty() {
            upstream.write_all(&extra).await?;
        }
        relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
            let idle_fut = relay::idle_watchdog(
                entry.clone(),
                idle.filter(|s| *s > 0).map(Duration::from_secs),
            );
            let mut client = relay::Counting::new(stream, entry);
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                _ = token.cancelled() => {}
                _ = idle_fut => {}
            }
        })
        .await;
    }
    Ok(())
}

/// Split `http://host[:port]/path` (or `https://...`) into its parts.
fn parse_absolute_uri(uri: &str) -> Result<(String, u16, String)> {
    let https = uri.starts_with("https://");
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);
    let default_port = if https { 443 } else { 80 };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        bail!("request is not in absolute form (not a proxy request): {uri:?}");
    }
    Ok((host, port, path.to_string()))
}
