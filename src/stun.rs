//! STUN wire codec (RFC 8489), shared by the TURN server's UDP, TCP and TLS
//! listeners. Pure parsing and serialisation — no I/O, no policy.
//!
//! Two rules here are worth reading before touching anything: MESSAGE-INTEGRITY
//! and FINGERPRINT cover different byte ranges *and* disagree about what the
//! header Length field should say while they are computed (see
//! [`verify_integrity`] and [`fingerprint`]), and MESSAGE-INTEGRITY is not
//! reliably the last attribute — pion and Firefox append FINGERPRINT after it,
//! so its offset must come from a forward scan and never from `len - 24`.
//!
//! The consumers (`turn.rs`) land in a later task; the `dead_code` allow covers
//! the window before those wire-ups.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;

/// No legitimate client sends a large STUN message; capping this bounds the
/// per-connection buffer an attacker can pin over TCP. It also caps a Send
/// indication's payload at ~2 KiB, which is far above any path MTU a WebRTC
/// endpoint will put on the wire.
///
/// The cap is on *received* messages only — [`Builder::finish`] never
/// truncates, so an inbound relayed datagram still reaches the client whole.
/// It matches `TurnConfig::max_datagram`'s default on purpose: raising that
/// knob past ~2000 widens the peer→client direction but not this one.
pub const MAX_MESSAGE: usize = 2048;

/// A 2 KiB message could carry 507 four-byte attributes; nothing real sends
/// more than a dozen. Bounding the count bounds the `Vec` a single datagram
/// can make us allocate and the work a 420 response can be made to do.
pub const MAX_ATTRIBUTES: usize = 64;

pub mod method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}

pub mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    /// We never verify or emit it, but we must recognise it: RFC 8489 §9.2.4
    /// makes it the one attribute besides FINGERPRINT that may legally follow
    /// MESSAGE-INTEGRITY, and 420-ing on it would break RFC 8489 clients that
    /// send both digests.
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

/// RFC 8489 Appendix A: the class bits are interleaved into the method bits.
pub fn message_type(m: u16, c: Class) -> u16 {
    let cls: u16 = match c {
        Class::Request => 0b00,
        Class::Indication => 0b01,
        Class::Success => 0b10,
        Class::Error => 0b11,
    };
    ((m & 0x1F80) << 2) | ((m & 0x0070) << 1) | (m & 0x000F) | ((cls & 0b10) << 7) | ((cls & 0b01) << 4)
}

pub fn decode_type(t: u16) -> (u16, Class) {
    let m = ((t & 0x3E00) >> 2) | ((t & 0x00E0) >> 1) | (t & 0x000F);
    let c = match (((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)) & 0b11 {
        0b00 => Class::Request,
        0b01 => Class::Indication,
        0b10 => Class::Success,
        _ => Class::Error,
    };
    (m, c)
}

/// CRC-32 as RFC 1952 §8 / zlib (reflected, poly 0xEDB88320, init and final
/// XOR 0xFFFFFFFF), which is what RFC 8489 §14.7 points at via ITU V.42.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// FINGERPRINT value for a message whose header Length ALREADY includes the
/// 8-byte FINGERPRINT TLV. `bytes` is the message truncated to exclude that
/// TLV — the length field is deliberately NOT rewritten, which is the exact
/// opposite of the MESSAGE-INTEGRITY rule.
pub fn fingerprint(bytes: &[u8]) -> u32 {
    crc32(bytes) ^ 0x5354_554E
}

/// A parsed STUN message borrowing its attribute values from the input buffer.
///
/// `attrs` stops at MESSAGE-INTEGRITY: bytes after it are outside the HMAC, so
/// letting [`first`] return one would hand callers an attacker-appended
/// USERNAME or LIFETIME that authenticated as if it had been signed.
#[derive(Debug)]
pub struct Message<'a> {
    pub method: u16,
    pub class: Class,
    pub txid: [u8; 12],
    pub attrs: Vec<(u16, &'a [u8])>,
    /// Byte offset of the MESSAGE-INTEGRITY TLV header, found by scanning
    /// forward. Feed it straight to [`verify_integrity`].
    pub mi_offset: Option<usize>,
    pub has_fingerprint: bool,
    /// Comprehension-required attribute types we do not implement, in wire
    /// order — the payload of a 420 response.
    pub unknown_required: Vec<u16>,
    /// The message truncated to its declared length, i.e. what the length
    /// rules above are computed over. Trailing bytes in the caller's buffer
    /// (UDP padding, the next TCP frame) are excluded.
    pub raw: &'a [u8],
}

/// Attribute types this server comprehends. A supported-set test, consulted
/// only for types below 0x8000 — the range test in [`parse`] already discarded
/// everything comprehension-optional, which is the whole point: libwebrtc sends
/// TURN-LOGGING-ID (0xff05) and MULTI-MAPPING (0xff04), and a 420 for those
/// leaves `TurnAllocateRequest::OnErrorResponse` with no matching branch, which
/// kills the port for good.
///
/// EVEN-PORT, RESERVATION-TOKEN and DONT-FRAGMENT are absent on purpose: 420 is
/// the RFC-prescribed way to say "unsupported", and clients retry without them.
fn understood(typ: u16) -> bool {
    matches!(
        typ,
        attr::MAPPED_ADDRESS
            | attr::USERNAME
            | attr::MESSAGE_INTEGRITY
            | attr::ERROR_CODE
            | attr::UNKNOWN_ATTRIBUTES
            | attr::CHANNEL_NUMBER
            | attr::LIFETIME
            | attr::XOR_PEER_ADDRESS
            | attr::DATA
            | attr::REALM
            | attr::NONCE
            | attr::XOR_RELAYED_ADDRESS
            | attr::REQUESTED_ADDRESS_FAMILY
            | attr::REQUESTED_TRANSPORT
            | attr::MESSAGE_INTEGRITY_SHA256
            | attr::XOR_MAPPED_ADDRESS
    )
}

/// Parse a STUN message. `None` means "drop it" — every rejection here is a
/// malformed or oversized message, never a protocol error worth answering.
///
/// All length arithmetic is `usize`; the u16 fields are widened before any
/// addition so a crafted length can overrun a bound instead of wrapping into
/// one.
pub fn parse(buf: &[u8]) -> Option<Message<'_>> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    // RFC 8489 §5: the two most significant bits are zero. This is also the
    // demux the TURN listener relies on to tell STUN from ChannelData.
    if buf[0] & 0xC0 != 0 {
        return None;
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE {
        return None;
    }
    let body = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !body.is_multiple_of(4) {
        return None;
    }
    let end = HEADER_LEN + body;
    if end > buf.len() || end > MAX_MESSAGE {
        return None;
    }

    let (method, class) = decode_type(u16::from_be_bytes([buf[0], buf[1]]));
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);

    let mut attrs: Vec<(u16, &[u8])> = Vec::new();
    let mut mi_offset: Option<usize> = None;
    let mut has_fingerprint = false;
    let mut unknown_required: Vec<u16> = Vec::new();

    let mut pos = HEADER_LEN;
    while pos < end {
        if end - pos < 4 {
            return None;
        }
        let typ = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let value_start = pos + 4;
        // The advance is over the PADDED length; the value is the unpadded
        // prefix. Received padding is never inspected — the RFC 5769 vectors
        // pad USERNAME with 0x20 spaces.
        let next = value_start + ((alen + 3) & !3);
        if next > end {
            return None;
        }
        let value = &buf[value_start..value_start + alen];

        if mi_offset.is_some() {
            // Past MESSAGE-INTEGRITY nothing is covered by the HMAC. RFC 8489
            // §9.2.4 allows exactly two attributes here; a comprehension-
            // required anything else is a client trying to smuggle unsigned
            // state past us, so drop the message rather than ignore the tail.
            match typ {
                // Same length and position rules as the pre-MI branch. This is
                // the branch nearly every real message takes — RFC 8489 puts
                // FINGERPRINT last, after MESSAGE-INTEGRITY, which is exactly
                // the shape pion and Firefox produce — so validating only in
                // the other branch would be validating the rare case.
                attr::FINGERPRINT if alen == 4 && next == end => has_fingerprint = true,
                attr::FINGERPRINT => return None,
                attr::MESSAGE_INTEGRITY_SHA256 => {}
                _ if typ >= 0x8000 => {}
                _ => return None,
            }
            pos = next;
            continue;
        }

        if attrs.len() >= MAX_ATTRIBUTES {
            return None;
        }
        attrs.push((typ, value));

        match typ {
            attr::MESSAGE_INTEGRITY => {
                // A short tag would make the HMAC comparison read whatever
                // follows it, so a wrong-sized MI is malformed, not absent.
                if alen != 20 {
                    return None;
                }
                mi_offset = Some(pos);
            }
            attr::FINGERPRINT => {
                // RFC 8489 §14.7: "MUST be the last attribute in the message".
                // Without the position check `has_fingerprint` would not mean
                // what its name and the echo rule imply.
                if alen != 4 || next != end {
                    return None;
                }
                // Not verified: it is a demux aid, not a security control, and
                // MESSAGE-INTEGRITY is what actually authenticates a request.
                // We only need to know whether to echo one (§5.2).
                has_fingerprint = true;
            }
            _ if typ >= 0x8000 => {}
            _ if understood(typ) => {}
            // Duplicates are folded: the 420 list is a set, and a message
            // repeating one unknown type should not inflate the response.
            _ if !unknown_required.contains(&typ) => unknown_required.push(typ),
            _ => {}
        }

        pos = next;
    }

    Some(Message {
        method,
        class,
        txid,
        attrs,
        mi_offset,
        has_fingerprint,
        unknown_required,
        raw: &buf[..end],
    })
}

/// First occurrence of `typ`. RFC 8489 §6.3: a repeated attribute is processed
/// once and the rest ignored, so callers must never scan for a later copy.
pub fn first<'a>(m: &Message<'a>, typ: u16) -> Option<&'a [u8]> {
    m.attrs.iter().find(|(t, _)| *t == typ).map(|(_, v)| *v)
}

/// Every occurrence of `typ`, in wire order — for the attributes RFC 8656
/// genuinely allows to repeat, such as XOR-PEER-ADDRESS in CreatePermission.
pub fn all<'a>(m: &Message<'a>, typ: u16) -> Vec<&'a [u8]> {
    m.attrs.iter().filter(|(t, _)| *t == typ).map(|(_, v)| *v).collect()
}

/// HMAC-SHA1 over `raw[..mi_offset]` with the header Length temporarily
/// rewritten to `mi_offset - HEADER_LEN + 24`. The rewrite is why MI cannot
/// be validated by assuming it sits at `len - 24`: pion and Firefox append
/// FINGERPRINT after it, so the offset must come from a forward scan.
pub fn verify_integrity(raw: &[u8], mi_offset: usize, key: &[u8]) -> bool {
    use hmac::{Mac, digest::KeyInit};
    // saturating: the offset is a caller-supplied usize, and a wrapped add
    // here would turn a bounds check into an out-of-range slice panic.
    if mi_offset.saturating_add(24) > raw.len() || mi_offset < HEADER_LEN {
        return false;
    }
    let mut scratch = raw[..mi_offset].to_vec();
    let adjusted = (mi_offset - HEADER_LEN + 24) as u16;
    scratch[2..4].copy_from_slice(&adjusted.to_be_bytes());
    let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(key) else {
        return false;
    };
    mac.update(&scratch);
    // verify_slice, not ==: the comparison is constant time.
    mac.verify_slice(&raw[mi_offset + 4..mi_offset + 24]).is_ok()
}

/// The long-term credential key: `MD5(username ":" realm ":" password)`.
///
/// No SASLprep/OpaqueString. RFC 8489 §9.2.2 asks for it, but libwebrtc applies
/// none and our credentials are TURN-REST base64 and ASCII user ids, where the
/// transform is the identity — running it would only risk disagreeing with the
/// clients we exist to serve.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::Digest;
    let mut h = md5::Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out);
    key
}

/// XOR an IPv6 address in place against `cookie || txid` (RFC 8489 §14.2). The
/// transform is its own inverse, so encode and decode share it.
fn xor_v6(octets: &mut [u8; 16], txid: &[u8; 12]) {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    for i in 0..4 {
        octets[i] ^= cookie[i];
    }
    for i in 0..12 {
        octets[4 + i] ^= txid[i];
    }
}

/// Decode an XOR-MAPPED-ADDRESS-shaped value (also XOR-PEER-ADDRESS and
/// XOR-RELAYED-ADDRESS). Trailing bytes are ignored and the reserved first byte
/// is not validated, per RFC 8489 §14.1.
///
/// This is a codec, not a policy gate: a v4-mapped v6 literal decodes as it was
/// written, so callers must run it through `Manager::canonicalize_ip` before
/// any denylist test (§8.1/§8.5) — otherwise `::ffff:127.0.0.1` walks past a
/// v4 rule.
pub fn parse_xor_addr(txid: &[u8; 12], value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
    match value[1] {
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            let x = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::from((Ipv4Addr::from(x), port)))
        }
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&value[4..20]);
            xor_v6(&mut o, txid);
            Some(SocketAddr::from((Ipv6Addr::from(o), port)))
        }
        _ => None,
    }
}

/// Encode an address as an XOR-MAPPED-ADDRESS-shaped value: 8 bytes for IPv4,
/// 20 for IPv6.
pub fn encode_xor_addr(txid: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0); // reserved
    let xport = (addr.port() ^ 0x2112).to_be_bytes();
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&xport);
            out.extend_from_slice(&(u32::from(v4) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&xport);
            let mut o = v6.octets();
            xor_v6(&mut o, txid);
            out.extend_from_slice(&o);
        }
    }
    out
}

/// Write the header Length field.
///
/// Callers must have checked the bound already ([`Builder::finish`] refuses an
/// oversized message outright). Clamping here instead would emit a header that
/// disagrees with the bytes behind it — and on the TCP/TLS listeners, where the
/// framer reads exactly `20 + declared` bytes, the surplus becomes the head of
/// the next frame and desynchronises that connection permanently.
fn set_body_len(buf: &mut [u8], body: usize) {
    debug_assert!(
        body <= u16::MAX as usize,
        "STUN body {body} overflows the length field"
    );
    let n = (body.min(u16::MAX as usize)) as u16;
    buf[2..4].copy_from_slice(&n.to_be_bytes());
}

/// Serialiser for a single message. Attributes go on in call order; the header
/// length, MESSAGE-INTEGRITY and FINGERPRINT are all settled by
/// [`Builder::finish`], which consumes the builder so a signed message cannot
/// be extended afterwards.
pub struct Builder {
    buf: Vec<u8>,
    /// Set when a pushed value could not be represented; `finish` then refuses.
    overflow: bool,
}

impl Builder {
    pub fn new(method: u16, class: Class, txid: [u8; 12]) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&message_type(method, class).to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // length, written by finish()
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        Builder {
            buf,
            overflow: false,
        }
    }

    /// Append a TLV, zero-padded to a multiple of 4. The declared length is the
    /// value length *before* padding.
    ///
    /// A value that will not fit the 16-bit length field is *recorded as an
    /// overflow and dropped*, not truncated: truncating would produce a TLV
    /// whose declared length disagrees with its contents. [`Builder::finish`]
    /// then refuses the whole message.
    pub fn push(&mut self, typ: u16, value: &[u8]) {
        if value.len() > u16::MAX as usize {
            self.overflow = true;
            return;
        }
        let n = value.len();
        self.buf.extend_from_slice(&typ.to_be_bytes());
        self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(self.buf.len() + ((4 - n % 4) % 4), 0);
    }

    pub fn push_u32(&mut self, typ: u16, v: u32) {
        self.push(typ, &v.to_be_bytes());
    }

    /// Append an XOR-encoded address, keyed by this message's own transaction
    /// id — taking it from the header rather than an argument removes the one
    /// way a caller can silently produce an address no client can decode.
    pub fn push_xor_addr(&mut self, typ: u16, addr: SocketAddr) {
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&self.buf[8..20]);
        let v = encode_xor_addr(&txid, addr);
        self.push(typ, &v);
    }

    /// ERROR-CODE (RFC 8489 §14.8): two zero bytes, the hundreds digit, the
    /// remainder, then the UTF-8 reason phrase.
    pub fn push_error(&mut self, code: u16, reason: &str) {
        let mut v = Vec::with_capacity(4 + reason.len());
        v.extend_from_slice(&[0, 0, (code / 100) as u8, (code % 100) as u8]);
        v.extend_from_slice(reason.as_bytes());
        self.push(attr::ERROR_CODE, &v);
    }

    /// UNKNOWN-ATTRIBUTES: the 420 list, one u16 per type, in wire order.
    pub fn push_unknown_attributes(&mut self, types: &[u16]) {
        let mut v = Vec::with_capacity(types.len() * 2);
        for t in types {
            v.extend_from_slice(&t.to_be_bytes());
        }
        self.push(attr::UNKNOWN_ATTRIBUTES, &v);
    }

    /// Finish the message: write the true final length, sign, then fingerprint.
    ///
    /// The order is the whole trick. MESSAGE-INTEGRITY is computed over the
    /// bytes so far with the length field pointing one attribute *past* them,
    /// while FINGERPRINT is computed over everything including the MI TLV with
    /// the length field left at its true final value — already counting the
    /// FINGERPRINT TLV that does not exist yet. Swapping the two rules produces
    /// a message every client rejects and every unit test that only checks
    /// "does it round-trip through my own code" accepts.
    /// Returns `None` when the message cannot be represented — an attribute
    /// longer than 65535 bytes, or a body that would overflow the 16-bit length
    /// field. The caller drops the message. Refusing is the only safe answer: a
    /// clamped length field desynchronises a TCP/TLS connection for good, and
    /// `debug_assert` alone would be compiled out in exactly the build where
    /// that matters.
    pub fn finish(mut self, key: Option<&[u8]>, fingerprint_it: bool) -> Option<Vec<u8>> {
        let mut total = self.buf.len() - HEADER_LEN;
        if key.is_some() {
            total += 24;
        }
        if fingerprint_it {
            total += 8;
        }
        if self.overflow || total > u16::MAX as usize {
            return None;
        }

        if let Some(k) = key {
            let mi_offset = self.buf.len();
            set_body_len(&mut self.buf, mi_offset - HEADER_LEN + 24);
            if let Some(tag) = hmac_sha1(k, &self.buf) {
                self.push(attr::MESSAGE_INTEGRITY, &tag);
            } else {
                // Only reachable if the HMAC refuses the key; emitting an
                // unsigned response is better than emitting a forged tag.
                total -= 24;
            }
        }
        set_body_len(&mut self.buf, total);

        if fingerprint_it {
            let crc = fingerprint(&self.buf);
            self.push_u32(attr::FINGERPRINT, crc);
        }
        Some(self.buf)
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Option<[u8; 20]> {
    use hmac::{Mac, digest::KeyInit};
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).ok()?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 20];
    tag.copy_from_slice(&out);
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 5769 §2.1 — sample request. This is THE vector that exercises the
    /// MESSAGE-INTEGRITY length rewrite, because MI is not the last attribute
    /// (FINGERPRINT follows it), exactly as pion and Firefox send.
    fn rfc5769_request() -> Vec<u8> {
        hex("000100582112a442b7e7a701bc34d686fa87dfae\
             802200105354554e207465737420636c69656e74\
             002400046e0001ff\
             80290008932ff9b151263b36\
             000600096576746a3a68367659202020\
             00080014\
             9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2\
             80280004e57a3bcf")
    }

    #[test]
    fn rfc5769_21_message_integrity_with_trailing_fingerprint() {
        let buf = rfc5769_request();
        let m = parse(&buf).expect("parses");
        assert_eq!(m.method, method::BINDING);
        assert_eq!(m.class, Class::Request);
        assert!(m.has_fingerprint);
        let mi = m.mi_offset.expect("MI located by scanning, not assumed last");
        // Short-term credential: the key IS the password bytes.
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";
        assert!(verify_integrity(&buf, mi, key));
        // A one-bit change to the key must fail — proves we are not
        // accidentally short-circuiting.
        assert!(!verify_integrity(&buf, mi, b"VOkJxbRl1RmTxUk/WvJxBu"));
    }

    #[test]
    fn rfc5769_21_fingerprint_keeps_the_full_length_field() {
        // The classic bug: FINGERPRINT's length rule is the OPPOSITE of
        // MESSAGE-INTEGRITY's. The header Length stays at its true final
        // value (which already counts the 8-byte FINGERPRINT TLV); only the
        // BYTES fed to the CRC are truncated.
        let buf = rfc5769_request();
        let crc = fingerprint(&buf[..buf.len() - 8]);
        assert_eq!(crc, 0xe57a3bcf);
    }

    #[test]
    fn rfc5769_24_long_term_credential_key_and_integrity() {
        // Username is the 6 katakana of "マトリックス"; realm "example.org";
        // password "TheMatrIX" (post-SASLprep, which is identity for us).
        let key = long_term_key("\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}", "example.org", "TheMatrIX");
        assert_eq!(key.to_vec(), hex("e8ca7ad59d5eb0518e312911d2dab2a9"));
        // ...and the message that key signs, so the whole long-term path is
        // pinned and not just the digest (spec §10.1).
        let buf = hex("000100602112a44278ad3433c6ad72c029da412e\
                       00060012e3839ee38388e383aae38383e382afe382b90000\
                       0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341\
                       0014000b6578616d706c652e6f726700\
                       00080014f67024656dd64a3e02b8e0712e85c9a28ca89666");
        let m = parse(&buf).expect("parses");
        assert!(verify_integrity(&buf, m.mi_offset.expect("MI present"), &key));
    }

    /// RFC 5769 §2.2 and §2.3 — the sample responses, byte for byte. The
    /// synthetic roundtrip tests below cannot catch a wrong XOR order because
    /// encode and decode share one helper, so the v6 X-Address has to be
    /// checked against bytes we did not produce. These also pad SOFTWARE with
    /// 0x20 spaces, which is why received padding must never be validated.
    #[test]
    fn rfc5769_22_23_sample_responses_decode_and_verify() {
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";
        for (raw, want) in [
            (
                "0101003c2112a442b7e7a701bc34d686fa87dfae\
                 8022000b7465737420766563746f7220\
                 002000080001a147e112a643\
                 000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7\
                 80280004c07d4c96",
                "192.0.2.1:32853",
            ),
            (
                "010100482112a442b7e7a701bc34d686fa87dfae\
                 8022000b7465737420766563746f7220\
                 002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9\
                 00080014a382954e4be67bf11784c97c8292c275bfe3ed41\
                 80280004c8fb0b4c",
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853",
            ),
        ] {
            let buf = hex(raw);
            let m = parse(&buf).expect("parses");
            assert_eq!(m.class, Class::Success);
            let v = first(&m, attr::XOR_MAPPED_ADDRESS).expect("XOR-MAPPED-ADDRESS");
            assert_eq!(parse_xor_addr(&m.txid, v).unwrap(), want.parse::<SocketAddr>().unwrap());
            assert!(verify_integrity(&buf, m.mi_offset.expect("MI present"), key));
            assert!(m.has_fingerprint);
            assert_eq!(
                fingerprint(&buf[..buf.len() - 8]),
                u32::from_be_bytes(buf[buf.len() - 4..].try_into().unwrap())
            );
        }
    }

    /// Bytes after MESSAGE-INTEGRITY are outside the HMAC, so they are either
    /// rejected or invisible — never merely "ignored" into a field a handler
    /// will read.
    #[test]
    fn nothing_after_message_integrity_is_trusted() {
        fn append(signed: &[u8], typ: u16, value: &[u8]) -> Vec<u8> {
            let mut out = signed.to_vec();
            out.extend_from_slice(&typ.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
            let body = (out.len() - HEADER_LEN) as u16;
            out[2..4].copy_from_slice(&body.to_be_bytes());
            out
        }

        let key = [1u8; 16];
        let mut b = Builder::new(method::ALLOCATE, Class::Request, [8u8; 12]);
        b.push(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        let signed = b.finish(Some(&key), false).expect("fits");

        // Comprehension-required: an appended LIFETIME must cost the sender
        // the whole message, not just the attribute.
        let forged = append(&signed, attr::LIFETIME, &3600u32.to_be_bytes());
        assert!(parse(&forged).is_none());

        // Comprehension-optional: legal to carry (pion puts FINGERPRINT here),
        // but still unsigned, so it must not reach a handler.
        let trailer = append(&signed, attr::SOFTWARE, b"evil");
        let m = parse(&trailer).expect("an optional trailer is legal");
        assert!(first(&m, attr::SOFTWARE).is_none());
        // The signature covers none of it, and stays valid regardless — which
        // is precisely why the trailer cannot be trusted.
        assert!(verify_integrity(&trailer, m.mi_offset.unwrap(), &key));
    }

    #[test]
    fn rfc8489_922_md5_wiring() {
        // Verify the MD5 plumbing before trusting anything above it.
        let key = long_term_key("user", "realm", "pass");
        assert_eq!(key.to_vec(), hex("8493fbc53ba582fb4c044c456bdc40eb"));
    }

    #[test]
    fn xor_mapped_address_v4_roundtrip() {
        // RFC 5769 §2.2: 192.0.2.1:32853 encodes to 0001a147e112a643.
        let txid = [0u8; 12];
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let v = encode_xor_addr(&txid, addr);
        assert_eq!(v, hex("0001a147e112a643"));
        assert_eq!(parse_xor_addr(&txid, &v).unwrap(), addr);
    }

    #[test]
    fn xor_mapped_address_v6_roundtrip() {
        // v6 XORs against cookie || transaction id, so the txid matters.
        let txid = hex("78ad3433c6ad72c029da412e");
        let txid: [u8; 12] = txid.try_into().unwrap();
        let addr: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap();
        let v = encode_xor_addr(&txid, addr);
        assert_eq!(v.len(), 20);
        assert_eq!(parse_xor_addr(&txid, &v).unwrap(), addr);
    }

    #[test]
    fn message_type_codec_roundtrips() {
        for (m, c, want) in [
            (method::BINDING, Class::Request, 0x0001u16),
            (method::BINDING, Class::Success, 0x0101),
            (method::ALLOCATE, Class::Request, 0x0003),
            (method::ALLOCATE, Class::Success, 0x0103),
            (method::ALLOCATE, Class::Error, 0x0113),
            (method::SEND, Class::Indication, 0x0016),
            (method::DATA, Class::Indication, 0x0017),
            (method::CHANNEL_BIND, Class::Request, 0x0009),
        ] {
            assert_eq!(message_type(m, c), want, "encode {m:#x}/{c:?}");
            assert_eq!(decode_type(want), (m, c), "decode {want:#x}");
        }
    }

    #[test]
    fn unknown_attributes_split_on_0x8000() {
        // A range test, never a list: libwebrtc sends TURN-LOGGING-ID
        // (0xff05) and MULTI-MAPPING (0xff04), both comprehension-optional.
        // 420-ing on those kills the port permanently.
        let mut b = Builder::new(method::ALLOCATE, Class::Request, [7u8; 12]);
        b.push(0xff05, b"logid");
        b.push(0x8000, b"\x00\x00\x00\x01");
        b.push(0x0018, b"\x80\x00\x00\x00"); // EVEN-PORT: required, unsupported
        let buf = b.finish(None, false).expect("fits");
        let m = parse(&buf).unwrap();
        assert_eq!(m.unknown_required, vec![0x0018]);
    }

    #[test]
    fn rejects_bad_cookie_short_buffer_and_overrun() {
        assert!(parse(&[0u8; 19]).is_none());
        let mut bad = rfc5769_request();
        bad[4] = 0x00; // break the magic cookie
        assert!(parse(&bad).is_none());
        // An attribute claiming more bytes than remain must not panic.
        // Byte 23 is the low half of the first attribute's Length field, so
        // SOFTWARE claims 255 bytes with only 84 left in the message.
        let mut over = rfc5769_request();
        over[23] = 0xff;
        assert!(parse(&over).is_none());
    }

    #[test]
    fn builder_signs_then_fingerprints_in_that_order() {
        let key = [9u8; 16];
        let mut b = Builder::new(method::ALLOCATE, Class::Success, [3u8; 12]);
        b.push_u32(attr::LIFETIME, 600);
        let buf = b.finish(Some(&key), true).expect("fits");
        let m = parse(&buf).unwrap();
        let mi = m.mi_offset.expect("signed");
        assert!(verify_integrity(&buf, mi, &key));
        assert!(m.has_fingerprint);
        // FINGERPRINT must be last, and computed over the signed bytes.
        assert_eq!(fingerprint(&buf[..buf.len() - 8]), u32::from_be_bytes(
            buf[buf.len() - 4..].try_into().unwrap()));
    }

    #[test]
    fn oversized_message_is_refused_not_clamped() {
        // A clamped length field declares one size and is followed by another.
        // On the TCP/TLS listeners the framer reads exactly `20 + declared`
        // bytes, so the surplus becomes the head of the next frame and
        // desynchronises that connection for good. debug_assert alone would be
        // compiled out in exactly the build where that matters.
        let mut b = Builder::new(method::DATA, Class::Indication, [1u8; 12]);
        b.push(attr::DATA, &vec![0u8; 65_535]);
        b.push_xor_addr(attr::XOR_PEER_ADDRESS, "203.0.113.1:9000".parse().unwrap());
        assert!(b.finish(None, false).is_none(), "body overflows the u16 length");

        // A single attribute too large to describe is refused, not truncated.
        let mut b = Builder::new(method::DATA, Class::Indication, [1u8; 12]);
        b.push(attr::DATA, &vec![0u8; 65_536]);
        assert!(b.finish(None, false).is_none());

        // The largest representable message still builds.
        let mut b = Builder::new(method::DATA, Class::Indication, [1u8; 12]);
        b.push(attr::DATA, &vec![0u8; 65_000]);
        assert!(b.finish(None, false).is_some());
    }

    #[test]
    fn fingerprint_must_be_well_formed_and_last_in_both_branches() {
        let key = [4u8; 16];

        // After MESSAGE-INTEGRITY -- the branch nearly every real message
        // takes, since RFC 8489 puts FINGERPRINT last.
        let mut b = Builder::new(method::BINDING, Class::Request, [2u8; 12]);
        b.push(attr::SOFTWARE, b"x");
        let signed = b.finish(Some(&key), false).expect("fits");
        let mut bad = signed.clone();
        bad.extend_from_slice(&[0x80, 0x28, 0x00, 0x08]); // FINGERPRINT, len 8
        bad.extend_from_slice(&[0u8; 8]);
        let n = (bad.len() - HEADER_LEN) as u16;
        bad[2..4].copy_from_slice(&n.to_be_bytes());
        assert!(parse(&bad).is_none(), "a wrong-length FINGERPRINT must be refused");

        // Not last: FINGERPRINT followed by another attribute.
        let mut b = Builder::new(method::BINDING, Class::Request, [3u8; 12]);
        b.push_u32(attr::FINGERPRINT, 0);
        b.push(attr::SOFTWARE, b"trailing");
        let buf = b.finish(None, false).expect("fits");
        assert!(
            parse(&buf).is_none(),
            "RFC 8489 14.7: FINGERPRINT MUST be the last attribute"
        );
    }
}
