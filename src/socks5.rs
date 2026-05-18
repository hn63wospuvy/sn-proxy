//! SOCKS5 server (RFC 1928) with optional username/password auth (RFC 1929).
//!
//! Only the `CONNECT` command is supported, which is what proxy clients
//! (browsers, curl, etc.) use.

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use anyhow::{Result, bail};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_REJECT: u8 = 0xFF;

/// Handle a single accepted SOCKS5 client connection end to end.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    negotiate_auth(&mut stream, &runtime).await?;
    let dst = read_request(&mut stream).await?;

    let (connect_timeout, keepalive, idle) = {
        let cfg = runtime.config.lock().unwrap();
        (cfg.connect_timeout_secs, cfg.keepalive_secs, cfg.idle_timeout_secs)
    };
    let target = match relay::connect(&dst, connect_timeout, keepalive).await {
        Ok(t) => t,
        Err(e) => {
            let _ = reply(&mut stream, 0x05).await; // connection refused
            bail!("connect to {dst} failed: {e}");
        }
    };
    // Success: BND.ADDR/BND.PORT reported as 0.0.0.0:0.
    stream
        .write_all(&[VER, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

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

/// Perform the SOCKS5 method-selection handshake and, if the proxy requires
/// it, the RFC 1929 username/password exchange.
async fn negotiate_auth(stream: &mut TcpStream, runtime: &ProxyRuntime) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        bail!("not a socks5 client");
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;

    let auth = runtime.config.lock().unwrap().auth.clone();
    match auth {
        Some(auth) => {
            if !methods.contains(&METHOD_USERPASS) {
                stream.write_all(&[VER, METHOD_REJECT]).await?;
                bail!("client does not support username/password auth");
            }
            stream.write_all(&[VER, METHOD_USERPASS]).await?;

            // RFC 1929: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
            let mut h = [0u8; 2];
            stream.read_exact(&mut h).await?;
            if h[0] != 0x01 {
                bail!("unsupported auth subnegotiation version");
            }
            let mut uname = vec![0u8; h[1] as usize];
            stream.read_exact(&mut uname).await?;
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut passwd = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut passwd).await?;

            let ok = auth.username.as_bytes() == uname.as_slice()
                && auth.password.as_bytes() == passwd.as_slice();
            if ok {
                stream.write_all(&[0x01, 0x00]).await?;
                Ok(())
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                bail!("authentication failed");
            }
        }
        None => {
            if !methods.contains(&METHOD_NO_AUTH) {
                stream.write_all(&[VER, METHOD_REJECT]).await?;
                bail!("client insists on auth but proxy has none configured");
            }
            stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
            Ok(())
        }
    }
}

/// Read the SOCKS5 request and return the destination as `host:port`.
async fn read_request(stream: &mut TcpStream) -> Result<String> {
    let mut req = [0u8; 4]; // VER | CMD | RSV | ATYP
    stream.read_exact(&mut req).await?;
    if req[0] != VER {
        bail!("bad request version");
    }
    let cmd = req[1];
    let atyp = req[3];

    let host = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            format!("[{}]", Ipv6Addr::from(a))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            stream.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            let _ = reply(stream, 0x08).await; // address type not supported
            bail!("unsupported address type");
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    if cmd != CMD_CONNECT {
        let _ = reply(stream, 0x07).await; // command not supported
        bail!("only the CONNECT command is supported");
    }
    Ok(format!("{host}:{port}"))
}

/// Send a SOCKS5 reply carrying only a status code.
async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream
        .write_all(&[VER, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
