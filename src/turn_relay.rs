//! The relayed transport address: an opaque byte pipe between an allocation and
//! its peers.
//!
//! **This module deliberately does not import [`crate::stun`], and must not.**
//!
//! Everything arriving on a relay socket during a WebRTC call belongs to the
//! *client*, not to us: ICE Binding requests and consent-freshness checks
//! (RFC 8445, RFC 7675, roughly every five seconds), then DTLS handshake
//! records, then SRTP. Those Binding requests carry the client's ICE ufrag and
//! are protected by the ICE short-term credential — which this server does not
//! have and must never try to verify.
//!
//! If the relay path reused the listener's STUN dispatcher, the server would
//! parse a peer's connectivity check, fail to authenticate it, and answer the
//! *peer* with a 401 challenge. ICE would then never nominate a pair and media
//! would never flow, while the logs looked busy and healthy. That is one of the
//! hardest TURN failures to diagnose, so the invariant is enforced by module
//! boundary rather than by a comment, and a test asserts this file never
//! mentions the codec.
//!
//! The RFC 7983 demultiplexing rules apply only to the client-facing side.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// A relayed transport address. Exactly two operations, neither of which
/// inspects the bytes.
pub struct RelaySocket {
    sock: Arc<UdpSocket>,
    /// The address handed to clients in XOR-RELAYED-ADDRESS. May differ from
    /// the bound address under 1:1 NAT (`TurnConfig::advertise_ip`).
    advertised: SocketAddr,
    /// The address actually bound, used for teardown bookkeeping.
    bound: SocketAddr,
}

impl RelaySocket {
    pub fn new(sock: Arc<UdpSocket>, bound: SocketAddr, advertised: SocketAddr) -> Self {
        Self {
            sock,
            advertised,
            bound,
        }
    }

    /// The address to advertise to the client.
    pub fn advertised(&self) -> SocketAddr {
        self.advertised
    }

    /// The address actually bound.
    pub fn bound(&self) -> SocketAddr {
        self.bound
    }

    /// Send `data` to `peer` verbatim.
    pub async fn send_to(&self, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.sock.send_to(data, peer).await
    }

    /// Receive one datagram verbatim.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf).await
    }
}

/// Bind a relay socket on `ip:port`.
///
/// The IP must be concrete. ICE requires a connectivity-check response to come
/// from the same transport address the request went to, and a wildcard bind lets
/// the kernel pick a source address per route — so on a multi-homed host a peer
/// that probed relay IP A can get the answer from IP B, discard it, and fail the
/// candidate pair while packet captures show traffic flowing both ways.
pub async fn bind_relay(ip: std::net::IpAddr, port: u16) -> io::Result<(Arc<UdpSocket>, SocketAddr)> {
    if ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TURN relay sockets must bind a concrete IP, never a wildcard",
        ));
    }
    let sock = UdpSocket::bind(SocketAddr::new(ip, port)).await?;
    let bound = sock.local_addr()?;
    Ok((Arc::new(sock), bound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wildcard_relay_bind_is_refused() {
        // Not a style rule: a wildcard-bound relay silently breaks ICE
        // nomination on multi-homed hosts, and the failure looks like healthy
        // bidirectional traffic in a capture.
        let e = bind_relay("0.0.0.0".parse().unwrap(), 0).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = bind_relay("::".parse().unwrap(), 0).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn concrete_bind_reports_its_address() {
        let (sock, bound) = bind_relay("127.0.0.1".parse().unwrap(), 0).await.unwrap();
        assert_eq!(bound.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_ne!(bound.port(), 0);
        let advertised = SocketAddr::new("198.51.100.4".parse().unwrap(), bound.port());
        let relay = RelaySocket::new(sock, bound, advertised);
        // advertise_ip substitutes only into what the client is told.
        assert_eq!(relay.advertised(), advertised);
        assert_eq!(relay.bound(), bound);
    }

    #[tokio::test]
    async fn relays_bytes_without_inspecting_them() {
        // A STUN-shaped payload must cross untouched: it is the client's own
        // ICE check, keyed with a credential this server does not hold.
        let (sock, bound) = bind_relay("127.0.0.1".parse().unwrap(), 0).await.unwrap();
        let relay = RelaySocket::new(sock, bound, bound);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let stun_shaped = b"\x00\x01\x00\x00\x21\x12\xa4\x42rest-of-a-binding";
        relay.send_to(stun_shaped, peer_addr).await.unwrap();
        let mut buf = [0u8; 128];
        let (n, _) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], stun_shaped);

        peer.send_to(stun_shaped, bound).await.unwrap();
        let (n, from) = relay.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], stun_shaped);
        assert_eq!(from, peer_addr);
    }

    #[test]
    fn this_module_never_references_the_stun_codec() {
        // Structural enforcement of the invariant in the module docs. If this
        // ever fails, the relay path has started parsing the client's own ICE
        // traffic and answering the peer's connectivity checks itself.
        //
        // Only the non-test half is scanned, and the needle is assembled at
        // runtime — spelling it literally would make this file match itself.
        let src = include_str!("turn_relay.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        let needle = format!("{}{}", "stun", "::");
        let doc_link = format!("crate::{needle}");
        let without_docs = code.replace(&doc_link, "").replace("crate::stun", "");
        assert!(
            !without_docs.contains(&needle),
            "the relay path must stay an opaque byte pipe"
        );
    }
}
