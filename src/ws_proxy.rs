//! WebSocket tunnelling proxy.
//!
//! A client opens a WebSocket connection to the listener; every binary/text
//! frame it sends is relayed verbatim to the destination TCP socket, and bytes
//! from the destination are streamed back as binary frames.
//!
//! The destination is the proxy's configured `forward_to`, or — when the
//! client supplies a `?target=host:port` query parameter — that address.

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use anyhow::{Result, bail};
use base64::Engine;
use sha1::{Digest, Sha1};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Magic GUID from RFC 6455 used to derive the handshake accept token.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADER: usize = 64 * 1024;
/// Largest single WebSocket frame payload accepted (16 MiB).
const MAX_FRAME: usize = 16 * 1024 * 1024;

// WebSocket opcodes (RFC 6455 §5.2).
const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;

/// Handle a single accepted WebSocket-proxy client connection.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    // Read the HTTP upgrade request head.
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
    let request_target = request_line.split_whitespace().nth(1).unwrap_or("");
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    // Must be a WebSocket upgrade request.
    let is_ws = header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let key = match (is_ws, header("sec-websocket-key")) {
        (true, Some(k)) => k.to_string(),
        _ => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            bail!("not a websocket upgrade request");
        }
    };

    // Optional Basic authentication (Authorization / Proxy-Authorization).
    let configured_auth = runtime.config.lock().unwrap().auth.clone();
    if let Some(auth) = configured_auth {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        let expected = format!("Basic {creds}");
        let provided = header("authorization").or_else(|| header("proxy-authorization"));
        if provided != Some(expected.as_str()) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\n\
                      WWW-Authenticate: Basic realm=\"sn-proxy\"\r\n\
                      Connection: close\r\n\r\n",
                )
                .await;
            bail!("websocket proxy authentication failed");
        }
    }

    // Resolve the destination: a `?target=` query parameter overrides the
    // configured fixed destination.
    let (forward_to, connect_timeout, keepalive, idle) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.forward_to.clone(),
            cfg.connect_timeout_secs,
            cfg.keepalive_secs,
            cfg.idle_timeout_secs,
        )
    };
    let dst = match target_from_query(request_target).or(forward_to) {
        Some(d) if !d.is_empty() => d,
        _ => {
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            bail!("websocket proxy has no destination configured");
        }
    };

    // Connect upstream before completing the handshake, so a failure is
    // reported as a plain HTTP error rather than a closed WebSocket.
    let upstream = match relay::connect(&dst, connect_timeout, keepalive).await {
        Ok(u) => u,
        Err(e) => {
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            bail!("connect to {dst} failed: {e}");
        }
    };

    // Complete the RFC 6455 handshake.
    let accept = {
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update(WS_GUID.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
        let (mut client_r, mut client_w) = stream.into_split();
        let (mut up_r, mut up_w) = upstream.into_split();

        // client (WebSocket frames) -> destination (raw bytes)
        let to_upstream = async {
            loop {
                match read_frame(&mut client_r).await? {
                    None => break,
                    Some((OP_CLOSE, _)) => break,
                    Some((OP_BINARY | OP_TEXT | OP_CONTINUATION, payload)) => {
                        up_w.write_all(&payload).await?;
                        entry
                            .bytes_sent
                            .fetch_add(payload.len() as u64, Ordering::Relaxed);
                    }
                    // Ping/Pong and other control frames are not relayed.
                    Some(_) => {}
                }
            }
            Ok::<(), std::io::Error>(())
        };

        // destination (raw bytes) -> client (binary WebSocket frames)
        let to_client = async {
            let mut b = vec![0u8; 16 * 1024];
            loop {
                let n = up_r.read(&mut b).await?;
                if n == 0 {
                    let _ = write_frame(&mut client_w, OP_CLOSE, &[]).await;
                    break;
                }
                write_frame(&mut client_w, OP_BINARY, &b[..n]).await?;
                entry.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok::<(), std::io::Error>(())
        };

        let idle_fut =
            relay::idle_watchdog(entry.clone(), idle.filter(|s| *s > 0).map(Duration::from_secs));
        tokio::select! {
            _ = to_upstream => {}
            _ = to_client => {}
            _ = token.cancelled() => {}
            _ = idle_fut => {}
        }
    })
    .await;
    Ok(())
}

/// Extract a `target=host:port` value from a request URI's query string.
fn target_from_query(request_target: &str) -> Option<String> {
    let query = request_target.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("target=") {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Minimal percent-decoder for query values (`host%3Aport` -> `host:port`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one WebSocket frame, returning its opcode and unmasked payload.
/// `Ok(None)` signals a clean end of stream.
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    use std::io::{Error, ErrorKind};

    let mut head = [0u8; 2];
    match r.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext) as usize;
    }
    if len > MAX_FRAME {
        return Err(Error::new(ErrorKind::InvalidData, "websocket frame too large"));
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }
    Ok(Some((opcode, payload)))
}

/// Write one unmasked, unfragmented WebSocket frame (server -> client).
async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    opcode: u8,
    data: &[u8],
) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | opcode); // FIN set
    let len = data.len();
    if len < 126 {
        header.push(len as u8);
    } else if len <= 0xFFFF {
        header.push(126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    w.write_all(&header).await?;
    w.write_all(data).await?;
    Ok(())
}
