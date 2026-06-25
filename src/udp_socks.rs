//! Pure SOCKS5 UDP-relay datagram framing (RFC 1928 §7) — no I/O.
//!
//! These helpers are consumed by the UDP ASSOCIATE relay in `socks5.rs`
//! (Tasks 7-8); the `dead_code` allow covers the window before those wire-ups.
#![allow(dead_code)]

use std::net::SocketAddr;

/// The destination address carried in a client→relay datagram header.
pub enum ParsedHost {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String),
}

/// A parsed client→relay UDP datagram header (§2.2).
pub struct UdpHeader {
    pub frag: u8,
    pub atyp: u8,
    pub host: ParsedHost,
    pub port: u16,
    /// Index in `buf` where the payload (`DATA`) begins.
    pub data_offset: usize,
}

/// Parse a client→relay datagram header. Returns `None` (caller silently drops)
/// on `RSV != 0`, `FRAG != 0`, a short buffer, or a domain length overrun.
pub fn parse_udp_request(buf: &[u8]) -> Option<UdpHeader> {
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return None; // RSV must be 0x0000
    }
    let frag = buf[2];
    if frag != 0x00 {
        return None; // no reassembly
    }
    let atyp = buf[3];
    let (host, addr_end) = match atyp {
        0x01 => {
            if buf.len() < 4 + 4 + 2 {
                return None;
            }
            let mut a = [0u8; 4];
            a.copy_from_slice(&buf[4..8]);
            (ParsedHost::V4(a), 8)
        }
        0x04 => {
            if buf.len() < 4 + 16 + 2 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[4..20]);
            (ParsedHost::V6(a), 20)
        }
        0x03 => {
            if buf.len() < 5 {
                return None;
            }
            let n = buf[4] as usize;
            let name_end = 5 + n;
            if buf.len() < name_end + 2 {
                return None; // length overrun / missing port
            }
            let name = String::from_utf8_lossy(&buf[5..name_end]).into_owned();
            (ParsedHost::Domain(name), name_end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([buf[addr_end], buf[addr_end + 1]]);
    let data_offset = addr_end + 2;
    Some(UdpHeader { frag, atyp, host, port, data_offset })
}

/// Build a relay→client reply header (`RSV=0000 FRAG=00 ATYP ADDR PORT`).
/// `remote` is the responder's literal IP — never a domain (§2.2).
pub fn build_udp_reply_header(remote: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match remote {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&remote.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};

    fn v4_req() -> Vec<u8> {
        // RSV=0000 FRAG=00 ATYP=01 1.2.3.4 :443 DATA="hi"
        let mut b = vec![0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB];
        b.extend_from_slice(b"hi");
        b
    }

    #[test]
    fn parses_v4_request() {
        let h = parse_udp_request(&v4_req()).unwrap();
        assert_eq!(h.frag, 0);
        assert_eq!(h.atyp, 0x01);
        assert!(matches!(h.host, ParsedHost::V4([1, 2, 3, 4])));
        assert_eq!(h.port, 443);
        assert_eq!(h.data_offset, 10);
    }

    #[test]
    fn parses_domain_request() {
        // RSV FRAG ATYP=03 len=3 "abc" :80
        let mut b = vec![0x00, 0x00, 0x00, 0x03, 3, b'a', b'b', b'c', 0x00, 0x50];
        b.extend_from_slice(b"X");
        let h = parse_udp_request(&b).unwrap();
        assert!(matches!(h.host, ParsedHost::Domain(ref d) if d == "abc"));
        assert_eq!(h.port, 80);
        assert_eq!(h.data_offset, 10); // 4 + 1 (len byte) + 3 (name) + 2 (port)
    }

    #[test]
    fn parses_v6_request() {
        let mut b = vec![0x00, 0x00, 0x00, 0x04];
        b.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        b.extend_from_slice(&9u16.to_be_bytes());
        let h = parse_udp_request(&b).unwrap();
        assert!(matches!(h.host, ParsedHost::V6(_)));
        assert_eq!(h.data_offset, 22);
        assert_eq!(h.port, 9);
    }

    #[test]
    fn drops_nonzero_frag() {
        let mut b = v4_req();
        b[2] = 0x01; // FRAG != 0
        assert!(parse_udp_request(&b).is_none());
    }

    #[test]
    fn drops_nonzero_rsv() {
        let mut b = v4_req();
        b[0] = 0x01; // RSV != 0
        assert!(parse_udp_request(&b).is_none());
    }

    #[test]
    fn drops_short_buffer() {
        assert!(parse_udp_request(&[0x00, 0x00, 0x00]).is_none());
        // v4 header claims 10 bytes but only 9 present
        assert!(parse_udp_request(&[0, 0, 0, 1, 1, 2, 3, 4, 0]).is_none());
    }

    #[test]
    fn drops_domain_len_overrun() {
        // ATYP=03 len=10 but only 2 name bytes follow
        let b = vec![0x00, 0x00, 0x00, 0x03, 10, b'a', b'b'];
        assert!(parse_udp_request(&b).is_none());
    }

    #[test]
    fn builds_v4_reply_header() {
        let h = build_udp_reply_header(SocketAddr::new(
            std::net::Ipv4Addr::new(8, 8, 4, 4).into(),
            53,
        ));
        assert_eq!(h, vec![0x00, 0x00, 0x00, 0x01, 8, 8, 4, 4, 0x00, 0x35]);
    }

    #[test]
    fn builds_v6_reply_header() {
        let h = build_udp_reply_header(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9));
        assert_eq!(h.len(), 22);
        assert_eq!(h[3], 0x04);
        assert_eq!(&h[20..22], &9u16.to_be_bytes());
    }
}
