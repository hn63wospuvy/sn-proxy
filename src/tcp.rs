//! Plain TCP forwarder: every connection accepted on the listen port is
//! relayed to a fixed `forward_to` destination configured on the proxy.
//!
//! Optionally the original client address is announced to the destination with
//! a PROXY protocol v1 header (`send_proxy_protocol`). Without it the
//! destination only ever sees this proxy's address, which quietly breaks
//! anything that reasons about the client IP — SPF checks, IP allow/deny
//! lists, per-client rate limits, access logs.

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use anyhow::{Result, bail};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Build the PROXY protocol v1 header line for a relayed connection.
///
/// `src` is the client as this proxy sees it, `dst` is the local address the
/// client connected to. Format (haproxy PROXY protocol spec, section 2.1):
///
/// ```text
/// PROXY TCP4 <src ip> <dst ip> <src port> <dst port>\r\n
/// ```
///
/// A listener bound to `[::]` reports IPv4 clients as IPv4-mapped IPv6
/// (`::ffff:1.2.3.4`), so both addresses are canonicalised first — announcing
/// `TCP6` with a mapped address is rejected by strict parsers. `UNKNOWN` is the
/// spec's escape hatch for anything that does not fit, and receivers must
/// accept it; it is emitted only when the two ends somehow disagree on family.
fn proxy_v1_header(src: SocketAddr, dst: SocketAddr) -> String {
    match (src.ip().to_canonical(), dst.ip().to_canonical()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            format!("PROXY TCP4 {s} {d} {} {}\r\n", src.port(), dst.port())
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            format!("PROXY TCP6 {s} {d} {} {}\r\n", src.port(), dst.port())
        }
        _ => "PROXY UNKNOWN\r\n".to_string(),
    }
}

/// Handle one accepted connection for a TCP-forwarder proxy.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let (dst, connect_timeout, keepalive, idle, send_proxy_protocol) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.forward_to.clone(),
            cfg.connect_timeout_secs,
            cfg.keepalive_secs,
            cfg.idle_timeout_secs,
            cfg.send_proxy_protocol,
        )
    };
    let dst = match dst {
        Some(d) if !d.is_empty() => d,
        _ => bail!("tcp proxy has no forward destination configured"),
    };

    let mut target = match relay::connect(&dst, connect_timeout, keepalive).await {
        Ok(t) => t,
        Err(e) => bail!("connect to {dst} failed: {e}"),
    };

    if send_proxy_protocol {
        // Read the local address before `stream` is moved into the relay
        // closure below, and write the header before any client byte reaches
        // the destination — the receiver parses it as the very first line of
        // the session, so a single byte out of order poisons the connection.
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        if let Err(e) = target.write_all(proxy_v1_header(peer, local).as_bytes()).await {
            bail!("write PROXY protocol header to {dst} failed: {e}");
        }
    }

    relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
        let idle_fut =
            relay::idle_watchdog(entry.clone(), idle.filter(|s| *s > 0).map(Duration::from_secs));
        let mut client = relay::Counting::new(stream, entry);
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut target) => {}
            _ = token.cancelled() => {}
            _ = idle_fut => {}
        }
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::proxy_v1_header;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_pair_uses_tcp4() {
        assert_eq!(
            proxy_v1_header(addr("203.0.113.7:52134"), addr("198.51.100.2:25")),
            "PROXY TCP4 203.0.113.7 198.51.100.2 52134 25\r\n"
        );
    }

    #[test]
    fn ipv6_pair_uses_tcp6() {
        assert_eq!(
            proxy_v1_header(addr("[2001:db8::1]:52134"), addr("[2001:db8::2]:25")),
            "PROXY TCP6 2001:db8::1 2001:db8::2 52134 25\r\n"
        );
    }

    #[test]
    fn mapped_ipv4_on_dual_stack_listener_is_unmapped() {
        // The common deployment: listener bound to `[::]`, so an IPv4 client
        // arrives as `::ffff:a.b.c.d`. Announcing that verbatim as TCP6 is
        // what strict receivers reject, so both ends are canonicalised.
        assert_eq!(
            proxy_v1_header(addr("[::ffff:203.0.113.7]:52134"), addr("[::ffff:198.51.100.2]:25")),
            "PROXY TCP4 203.0.113.7 198.51.100.2 52134 25\r\n"
        );
    }

    #[test]
    fn mixed_families_fall_back_to_unknown() {
        // No valid v1 line can describe a v4 source with a v6 destination;
        // UNKNOWN is the spec's escape hatch and receivers must accept it.
        assert_eq!(
            proxy_v1_header(addr("203.0.113.7:52134"), addr("[2001:db8::2]:25")),
            "PROXY UNKNOWN\r\n"
        );
    }

    #[test]
    fn header_is_a_single_crlf_terminated_line() {
        // The receiver reads exactly one line; an embedded newline would make
        // the remainder look like protocol data.
        let header = proxy_v1_header(addr("203.0.113.7:1"), addr("198.51.100.2:25"));
        assert!(header.ends_with("\r\n"));
        assert_eq!(header.matches('\n').count(), 1);
        assert!(header.len() <= 107, "v1 header is capped at 107 bytes");
    }
}
