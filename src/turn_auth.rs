//! TURN long-term credentials (coturn's "REST API" scheme, `draft-uberti-behave-
//! turn-rest-00`) and a stateless NONCE. Pure computation: no I/O, no ambient
//! clock, no state. `now` is always an argument, which is what makes the expiry
//! and nonce windows testable at all — and the nonce needs no server-side table,
//! so there is nothing to reap and nothing for a flood of spoofed source
//! addresses to grow.
//!
//! Two things here are load-bearing and easy to get subtly wrong:
//!
//! 1. **The short-secret guard in [`credential_key`] is the last line of
//!    defence, not a convenience check.** `Hmac::<Sha1>::new_from_slice(b"")`
//!    *succeeds* — HMAC accepts a zero-length key without complaint — so with an
//!    unset secret every derivation still produces a key, every attacker-minted
//!    MESSAGE-INTEGRITY still verifies, and the REST scheme being the server's
//!    only auth path means the result is a fully open relay that looks
//!    authenticated in every log. Config validation is supposed to prevent that,
//!    but a config restored from RocksDB with the field absent deserialises to
//!    `None`, so the guard is repeated here where the key is actually made.
//!
//! 2. **The nonce MAC covers the timestamp in its exact serialised hex form** —
//!    the same bytes [`check_nonce`] slices back out of the string, never a
//!    re-serialisation of the parsed integer. Round-tripping through `u32` and
//!    reformatting would validate fine in tests and then reject a real nonce the
//!    moment any formatting detail differed.
//!
//! The consumers (`turn.rs`) land in a later task; the `dead_code` allow covers
//! the window before those wire-ups.
#![allow(dead_code)]

use crate::stun;
use base64::Engine as _;
use hmac::{Mac, digest::KeyInit};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// Below this, refuse to derive a credential key at all. 16 bytes of a
/// high-entropy secret puts brute-force of the REST password out of reach; the
/// value that matters most is that *zero* is on the wrong side of it (see the
/// module docs).
pub const MIN_SECRET_LEN: usize = 16;

/// How long an issued nonce stays valid. Long enough that a client never
/// re-authenticates mid-call by accident, short enough that a nonce lifted off
/// the wire is worthless within one media session.
pub const NONCE_WINDOW: u64 = 600;

/// Future-dated tolerance. A nonce cannot legitimately be from the future, but
/// a load-balanced pair of servers sharing a secret can disagree by a second or
/// two, and rejecting those would produce inexplicable 438 loops.
pub const NONCE_SKEW: u64 = 5;

/// Total nonce length: 8 hex (timestamp) + 8 hex (salt) + 16 hex (64-bit tag).
/// Fixed width is what lets [`check_nonce`] slice without bounds maths, and it
/// is far below RFC 8489 §14.10's 763-byte ceiling and the 127-byte practical
/// limit clients assume.
const NONCE_LEN: usize = 32;

/// Why the credential was refused. Every variant maps to a 401 on the wire
/// (RFC 8656 §7.2) — the distinctions exist for logs and metrics, not for the
/// response, because telling a client *which* check failed is a free oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The static secret is missing or shorter than [`MIN_SECRET_LEN`].
    NoSecret,
    /// The username is not `<expiry>:<userid>` with both halves non-empty.
    Malformed,
    /// The embedded expiry is in the past.
    Expired,
    /// The expiry is further ahead than the configured horizon.
    Horizon,
    /// MESSAGE-INTEGRITY did not verify under the derived key.
    BadIntegrity,
}

/// A parsed REST username. `userid` — not the full username — is what quota and
/// RFC 8656 §6.2's 441 anti-hijack check key on: the timestamp rotates, so a
/// per-username limit caps nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub userid: String,
    pub expiry: u64,
}

/// The REST password: `base64(HMAC-SHA1(secret, username))`.
///
/// Standard RFC 4648 §4 alphabet **with** padding. Not base64url, not unpadded —
/// coturn and every client's credential generator use `STANDARD`, and a
/// mismatch here produces a key that differs in every byte, surfacing as a
/// blanket 401 with nothing in the logs to explain it.
///
/// Deliberately *un*guarded on secret length so the admin API can mint
/// credentials with the same primitive; [`credential_key`] owns the guard,
/// because that is the function on the authentication path.
pub fn rest_password(secret: &[u8], username: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Split `<expiry>:<userid>` and check the expiry against `now` and `horizon`.
///
/// Both halves must be non-empty. A bare timestamp with no userid is a legal
/// coturn username, but it collapses every client into one quota bucket and one
/// 441 identity, so it is refused here rather than silently degrading both.
///
/// The horizon cap is a deliberate divergence from coturn, which accepts any
/// future timestamp: without it a credential minted with an expiry in 2099 is
/// valid forever, and a single leak is unrevocable short of rotating the secret.
pub fn parse_username(username: &str, now: u64, horizon: u64) -> Result<Credential, AuthError> {
    // `split_once`, not `split`/`rsplit`: only the FIRST colon delimits, since a
    // userid is free to contain colons of its own.
    let (ts, userid) = username.split_once(':').ok_or(AuthError::Malformed)?;
    if ts.is_empty() || userid.is_empty() {
        return Err(AuthError::Malformed);
    }
    // Digits only. `u64::from_str` would also accept a leading '+', which is
    // harmless for the HMAC (it covers the literal username) but would let two
    // spellings of one timestamp through the same checks.
    if !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::Malformed);
    }
    let expiry: u64 = ts.parse().map_err(|_| AuthError::Malformed)?;
    if expiry <= now {
        return Err(AuthError::Expired);
    }
    if expiry - now > horizon {
        return Err(AuthError::Horizon);
    }
    Ok(Credential { userid: userid.to_string(), expiry })
}

/// Derive the RFC 8489 §9.2.2 long-term key for a REST credential:
/// `MD5(username ":" realm ":" base64(HMAC-SHA1(secret, username)))`.
///
/// Returns [`AuthError::NoSecret`] for a secret under [`MIN_SECRET_LEN`] — the
/// guard described in the module docs. Note it refuses *before* touching HMAC,
/// so a short secret can never produce a key that some later refactor might
/// accidentally use.
///
/// No SASLprep/OpaqueString normalisation, matching libwebrtc (which applies
/// none) and coturn's REST path (which does not call its `SASLprep()`). Our
/// inputs are ASCII by construction — decimal timestamp, base64 password,
/// [`realm_is_valid`] realm — where the transform is the identity function, so
/// implementing it could only introduce divergence.
pub fn credential_key(secret: &str, username: &str, realm: &str) -> Result<[u8; 16], AuthError> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(AuthError::NoSecret);
    }
    let password = rest_password(secret.as_bytes(), username);
    Ok(stun::long_term_key(username, realm, &password))
}

/// The key the stateless nonce is MAC'd under. Distinct from the static secret
/// by construction — see [`nonce_key`].
pub struct NonceKey([u8; 32]);

impl NonceKey {
    /// The raw 32 bytes. Exposed for the domain-separation test; nothing on the
    /// request path needs it.
    pub fn raw(&self) -> &[u8] {
        &self.0
    }
}

/// Redacted: a whole `TurnConfig` gets formatted into error paths, and key
/// material must not reach `tracing` output at any level.
impl std::fmt::Debug for NonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NonceKey(<redacted>)")
    }
}

/// Derive the nonce key: `SHA-256(b"sn-proxy-turn-nonce-v1\0" || secret)`.
///
/// The label (and its NUL terminator, so no secret can extend it into another
/// label) is what keeps this key separate from the one `rest_password` uses.
/// Reusing the static secret directly would put two HMAC constructions under one
/// key over message spaces — `"<digits>:<userid>"` and `"<ip:port>|<hex>|<hex>"`
/// — that are only *incidentally* disjoint: one loosened parser on either side
/// and a nonce becomes a credential-forgery oracle.
pub fn nonce_key(secret: &str) -> NonceKey {
    NonceKey(sha256::digest(&[b"sn-proxy-turn-nonce-v1\0", secret.as_bytes()]))
}

/// Issue a nonce bound to `peer` and `now`:
/// `hex(u32 now) || hex(u32 salt) || hex(HMAC-SHA1(k, msg)[..8])`, where
/// `msg` is `"<ip:port>|<ts_hex>|<salt_hex>"`.
///
/// **`peer` is the full socket address, IP *and* port.** RFC 8489 §9.2.4: "The
/// server MUST NOT choose the same NONCE for two requests unless they have the
/// same source IP address and port." Binding to the IP alone hands two clients
/// behind one NAT an interchangeable nonce.
///
/// The `|` separators are what make the MAC input injective. The two hex fields
/// are fixed-width today, so bare concatenation would *happen* to be unambiguous
/// — but the peer string is not, and the day either width changes,
/// `("1.2.3.4:5", "60…")` and `("1.2.3.4:56", "0…")` become MAC-equivalent with
/// nothing to fail loudly. The separators cost three bytes and remove the class.
///
/// The salt is fresh entropy per issue, which is RFC 8656 §5's "SHOULD generate
/// a new random nonce" — without it two nonces issued to one peer inside the
/// same second would be byte-identical.
///
/// Callers must pass the *canonicalised* peer address (see
/// `Manager::canonicalize_ip`) to both this and [`check_nonce`]: `1.2.3.4:5` and
/// `[::ffff:1.2.3.4]:5` format differently and would not validate against each
/// other.
pub fn issue_nonce(k: &NonceKey, peer: SocketAddr, now: u64) -> String {
    let mut salt = [0u8; 4];
    if getrandom::fill(&mut salt).is_err() {
        // `getrandom` does not fail on any platform we build for, but panicking
        // here would put a remote DoS in the packet path. The salt is not
        // secret — it only keeps same-second nonces distinct, and the MAC still
        // authenticates whatever value goes in — so a counter is a safe
        // degradation rather than a security hole.
        static FALLBACK: AtomicU32 = AtomicU32::new(0);
        salt = FALLBACK.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    }
    let ts_hex = format!("{:08x}", now as u32);
    let salt_hex = hex(&salt);
    let mut nonce = String::with_capacity(NONCE_LEN);
    nonce.push_str(&ts_hex);
    nonce.push_str(&salt_hex);
    nonce.push_str(&hex(&tag(k, peer, &ts_hex, &salt_hex)));
    nonce
}

/// Validate a nonce: recompute the MAC over the bytes actually present, compare
/// in constant time, then check the window.
///
/// The MAC is checked before the window on purpose. Both outcomes are one
/// `false` to the caller (which answers 438 with a fresh nonce either way), so
/// there is nothing to gain by short-circuiting on the cheap check, and doing
/// the expensive one first keeps a stale-but-genuine nonce and a forged one on
/// the same code path.
///
/// Never panics: a nonce that is not exactly [`NONCE_LEN`] ASCII characters is
/// rejected before any slicing, which is what makes the fixed-index `split_at`
/// calls below safe on arbitrary attacker input.
pub fn check_nonce(k: &NonceKey, peer: SocketAddr, nonce: &str, now: u64) -> bool {
    if nonce.len() != NONCE_LEN || !nonce.is_ascii() {
        return false;
    }
    let (ts_hex, rest) = nonce.split_at(8);
    let (salt_hex, tag_hex) = rest.split_at(8);

    // MAC the slices verbatim — the exact bytes that arrived, never a
    // re-serialisation of a parsed value (module docs, point 2).
    let mut got = [0u8; 8];
    if !unhex(tag_hex, &mut got) {
        return false;
    }
    // Constant-time: `verify_truncated_left` folds the comparison so the number
    // of matching leading bytes is not observable. Comparing the hex strings
    // with `==` would leak it one byte at a time.
    let mac = mac(k, peer, ts_hex, salt_hex);
    if mac.verify_truncated_left(&got).is_err() {
        return false;
    }

    let Ok(ts) = u32::from_str_radix(ts_hex, 16) else {
        return false;
    };
    // Wrapping u32 arithmetic on purpose: the timestamp is serialised modulo
    // 2^32, so comparing in the same space keeps validation correct across the
    // 2106 rollover instead of rejecting every nonce for 600 seconds.
    let now32 = now as u32;
    let age = now32.wrapping_sub(ts); // seconds since issue
    let ahead = ts.wrapping_sub(now32); // seconds into the future
    age <= NONCE_WINDOW as u32 || ahead <= NONCE_SKEW as u32
}

/// The nonce MAC, keyed on the derived nonce key.
fn mac(k: &NonceKey, peer: SocketAddr, ts_hex: &str, salt_hex: &str) -> HmacSha1 {
    let mut mac = HmacSha1::new_from_slice(&k.0).expect("HMAC accepts any key length");
    // `SocketAddr`'s Display is `1.2.3.4:5` / `[::1]:5` — port included, and
    // unambiguous in both families.
    mac.update(format!("{peer}|{ts_hex}|{salt_hex}").as_bytes());
    mac
}

/// The first 8 bytes of the nonce MAC. 64 bits is ample: an attacker gets one
/// online guess per request against a key they never see.
fn tag(k: &NonceKey, peer: SocketAddr, ts_hex: &str, salt_hex: &str) -> [u8; 8] {
    let full = mac(k, peer, ts_hex, salt_hex).finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

/// Is `realm` usable as a STUN REALM? Non-empty, at most 127 characters, and
/// printable ASCII excluding space, tab, `"`, `'`, `\`, CR and LF (RFC 8489
/// §14.9 plus coturn's `is_secure_string`).
///
/// The empty case is not cosmetic. libwebrtc's `set_realm()` only recomputes the
/// credential hash when the value *changes*, and `realm_` starts as `""` — so a
/// 401 carrying `REALM=""` never triggers `UpdateHash()`, the hash stays empty,
/// and every subsequent MESSAGE-INTEGRITY is computed over an empty key. Chrome
/// then fails 100% of the time, with the server's logs showing only bad
/// integrity.
pub fn realm_is_valid(realm: &str) -> bool {
    // `is_ascii_graphic()` is exactly 0x21..=0x7E, which already excludes space,
    // tab, CR, LF, DEL and everything non-ASCII; the three quote/escape
    // characters are what coturn additionally refuses.
    !realm.is_empty()
        && realm.len() <= 127
        && realm.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b'\\'))
}

/// Lowercase hex. Lowercase specifically: the MAC covers these exact bytes, so
/// issue and check must agree on case.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode exactly `out.len() * 2` hex characters. Returns false on any non-hex
/// byte or a length mismatch — `u64::from_str_radix` would accept a leading '+'
/// and a mixed-case spelling, both of which must not round-trip to a valid tag.
fn unhex(s: &str, out: &mut [u8]) -> bool {
    if s.len() != out.len() * 2 {
        return false;
    }
    let b = s.as_bytes();
    for (i, byte) in out.iter_mut().enumerate() {
        let (hi, lo) = (nibble(b[i * 2]), nibble(b[i * 2 + 1]));
        match (hi, lo) {
            (Some(h), Some(l)) => *byte = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None, // uppercase is rejected: `hex` never emits it
    }
}

/// SHA-256 (FIPS 180-4), inline because `sha2` is not a dependency of this crate
/// and the nonce-key derivation is the only place the server needs a second
/// hash function. Pinned to the FIPS vectors in the tests below, including a
/// two-block message so the padding and length-append paths are both covered.
///
/// This is a key-derivation step over a local secret, not a bulk primitive:
/// there is no timing-sensitive input and nothing to be gained from a faster
/// implementation.
mod sha256 {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];

    /// Hash the concatenation of `parts`. Buffered rather than streaming: the
    /// only input is a 23-byte label plus a short secret, so one allocation is
    /// both cheaper and easier to read than a block-state machine.
    pub fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c,
            0x1f83_d9ab, 0x5be0_cd19,
        ];

        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut msg = Vec::with_capacity(total + 72);
        for p in parts {
            msg.extend_from_slice(p);
        }
        // Pad: 0x80, zeros to a 56 mod 64 boundary, then the length in BITS.
        let bits = (total as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bits.to_be_bytes());

        let mut w = [0u32; 64];
        for block in msg.chunks_exact(64) {
            for (i, word) in w.iter_mut().take(16).enumerate() {
                *word = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let a = w[i - 15];
                let b = w[i - 2];
                let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
                let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut v = h;
            for (k, wi) in K.iter().zip(w.iter()) {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(*k)
                    .wrapping_add(*wi);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for (hi, vi) in h.iter_mut().zip(v.iter()) {
                *hi = hi.wrapping_add(*vi);
            }
        }

        let mut out = [0u8; 32];
        for (chunk, hi) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&hi.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "203.0.113.9:51000";
    fn peer() -> SocketAddr {
        PEER.parse().unwrap()
    }

    /// A secret long enough to clear [`MIN_SECRET_LEN`]. The plan's vector
    /// secret ("north") deliberately does not.
    const SECRET: &str = "0123456789abcdef";

    #[test]
    fn rest_vector_matches_coturn() {
        // Verified end to end against openssl: secret "north",
        // username "12334939:mbzrxpgjys", realm "north.example".
        let pw = rest_password(b"north", "12334939:mbzrxpgjys");
        assert_eq!(pw, "Iq7YXkRon8YXJfdN1Ke9EZOw1UE=");
        // Standard base64 WITH padding — not base64url, not unpadded.
        assert!(pw.ends_with('='));
        assert_eq!(pw.len(), 28);
        // The published vector's secret is 5 bytes, so `credential_key` cannot
        // be the path here: MIN_SECRET_LEN refuses it, and correctly so. Both
        // pinned values are unchanged — the second step is just taken through
        // the function `credential_key` itself calls, and
        // `credential_key_is_rest_password_plus_long_term_key` below pins that
        // composition with a secret that clears the guard.
        let key = stun::long_term_key("12334939:mbzrxpgjys", "north.example", &pw);
        assert_eq!(
            key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "280dbc5cb2327b293dbf2ef07af6f50e"
        );
        assert!(matches!(
            credential_key("north", "12334939:mbzrxpgjys", "north.example"),
            Err(AuthError::NoSecret)
        ));
    }

    #[test]
    fn credential_key_is_rest_password_plus_long_term_key() {
        // Recovers what the vector test can no longer assert through
        // `credential_key`: that it is exactly MD5(user:realm:rest_password),
        // not some other composition that happens to be 16 bytes.
        let key = credential_key(SECRET, "1000600:alice", "example.org").unwrap();
        let pw = rest_password(SECRET.as_bytes(), "1000600:alice");
        assert_eq!(key, stun::long_term_key("1000600:alice", "example.org", &pw));
    }

    #[test]
    fn empty_or_short_secret_authenticates_nothing() {
        // Hmac::new_from_slice(b"") SUCCEEDS -- HMAC accepts a zero-length
        // key -- so without this guard an unset secret is an open relay with
        // correct-looking MESSAGE-INTEGRITY.
        assert!(matches!(credential_key("", "1:u", "r"), Err(AuthError::NoSecret)));
        assert!(matches!(credential_key("short", "1:u", "r"), Err(AuthError::NoSecret)));
        assert!(credential_key("0123456789abcdef", "1:u", "r").is_ok());
    }

    #[test]
    fn hmac_really_does_accept_an_empty_key() {
        // The premise of the guard above, asserted rather than assumed: if this
        // ever starts erroring, the guard is still correct but its rationale
        // has changed and the module docs need revisiting.
        assert!(HmacSha1::new_from_slice(b"").is_ok());
        assert_eq!(rest_password(b"", "1:u").len(), 28);
    }

    #[test]
    fn username_must_carry_a_userid_and_a_future_expiry() {
        let now = 1_000_000u64;
        let horizon = 86_400u64;
        let c = parse_username("1000600:alice", now, horizon).unwrap();
        assert_eq!(c.userid, "alice");
        assert_eq!(c.expiry, 1_000_600);
        // Expired.
        assert!(matches!(parse_username("999999:alice", now, horizon), Err(AuthError::Expired)));
        // A bare timestamp is legal in coturn but makes the per-user quota a
        // no-op, so we refuse it.
        assert!(matches!(parse_username("1000600", now, horizon), Err(AuthError::Malformed)));
        assert!(matches!(parse_username("1000600:", now, horizon), Err(AuthError::Malformed)));
        // Far-future expiry: coturn accepts it forever, we cap the horizon.
        assert!(matches!(parse_username("9999999999:alice", now, horizon), Err(AuthError::Horizon)));
        // The userid may itself contain colons; only the first splits.
        assert_eq!(parse_username("1000600:a:b", now, horizon).unwrap().userid, "a:b");
    }

    #[test]
    fn username_edges_do_not_panic_or_overflow() {
        let (now, horizon) = (1_000_000u64, 86_400u64);
        // Empty timestamp half, non-numeric, and the '+' spelling `u64::from_str`
        // would otherwise accept.
        assert!(matches!(parse_username(":alice", now, horizon), Err(AuthError::Malformed)));
        assert!(matches!(parse_username("abc:alice", now, horizon), Err(AuthError::Malformed)));
        assert!(matches!(parse_username("+1000600:alice", now, horizon), Err(AuthError::Malformed)));
        assert!(matches!(parse_username("", now, horizon), Err(AuthError::Malformed)));
        // Wider than u64 -> Malformed, not a wrap.
        let huge = "9".repeat(25);
        assert!(matches!(
            parse_username(&format!("{huge}:alice"), now, horizon),
            Err(AuthError::Malformed)
        ));
        // Expiry exactly at `now` is not "in the future".
        assert!(matches!(parse_username("1000000:alice", now, horizon), Err(AuthError::Expired)));
        // Exactly at the horizon is still inside it.
        assert!(parse_username("1086400:alice", now, horizon).is_ok());
        assert!(matches!(parse_username("1086401:alice", now, horizon), Err(AuthError::Horizon)));
    }

    #[test]
    fn nonce_roundtrips_and_expires() {
        let k = nonce_key("0123456789abcdef");
        let n = issue_nonce(&k, peer(), 1_000_000);
        assert!(n.len() < 128);
        assert!(check_nonce(&k, peer(), &n, 1_000_000));
        assert!(check_nonce(&k, peer(), &n, 1_000_000 + NONCE_WINDOW - 1));
        assert!(!check_nonce(&k, peer(), &n, 1_000_000 + NONCE_WINDOW + 1));
    }

    #[test]
    fn nonce_is_bound_to_ip_and_port() {
        // RFC 8489 9.2.4: the same NONCE may not be issued to two requests
        // unless source IP AND PORT match. Binding to the IP alone would give
        // two clients behind one NAT an identical nonce.
        let k = nonce_key("0123456789abcdef");
        let n = issue_nonce(&k, peer(), 1_000_000);
        let same_ip_other_port: SocketAddr = "203.0.113.9:51001".parse().unwrap();
        let other_ip: SocketAddr = "203.0.113.10:51000".parse().unwrap();
        assert!(!check_nonce(&k, same_ip_other_port, &n, 1_000_000));
        assert!(!check_nonce(&k, other_ip, &n, 1_000_000));
    }

    #[test]
    fn two_nonces_for_one_peer_differ() {
        // A random salt satisfies RFC 8656 §5's "new random nonce".
        let k = nonce_key("0123456789abcdef");
        let a = issue_nonce(&k, peer(), 1_000_000);
        let b = issue_nonce(&k, peer(), 1_000_000);
        assert_ne!(a, b);
        assert!(check_nonce(&k, peer(), &a, 1_000_000));
        assert!(check_nonce(&k, peer(), &b, 1_000_000));
    }

    #[test]
    fn forged_nonce_is_rejected() {
        let k = nonce_key("0123456789abcdef");
        let mut n = issue_nonce(&k, peer(), 1_000_000).into_bytes();
        let last = n.len() - 1;
        n[last] = if n[last] == b'a' { b'b' } else { b'a' };
        assert!(!check_nonce(&k, peer(), &String::from_utf8(n).unwrap(), 1_000_000));
        // Garbage must not panic.
        assert!(!check_nonce(&k, peer(), "", 1_000_000));
        assert!(!check_nonce(&k, peer(), "zzzz", 1_000_000));
    }

    #[test]
    fn malformed_nonces_are_rejected_without_panicking() {
        // Every index in `check_nonce` is fixed, so anything that is not exactly
        // NONCE_LEN ASCII bytes has to be turned away before the slicing. Two
        // of these are multi-byte UTF-8 whose `len()` is 32 bytes but whose
        // byte 8 is mid-character — a `split_at` on those would panic.
        let k = nonce_key(SECRET);
        let good = issue_nonce(&k, peer(), 1_000_000);
        for bad in [
            String::new(),
            "zzzz".into(),
            "z".repeat(31),
            "z".repeat(33),
            "z".repeat(32),                 // right length, not hex
            good.to_uppercase(),            // case matters: the MAC is over bytes
            format!("{}x", &good[..31]),    // non-hex byte inside the tag
            "\u{00e9}".repeat(16),          // 32 bytes, 16 chars, boundary at 8 is mid-char
            format!("{}\u{00e9}", &good[..30]),
            format!(" {}", &good[..31]),    // leading space
            format!("+{}", &good[1..]),     // the '+' from_str_radix would accept
        ] {
            assert!(!check_nonce(&k, peer(), &bad, 1_000_000), "accepted {bad:?}");
        }
        // Sanity: the untouched nonce still validates, so the loop above is not
        // passing because everything is rejected.
        assert!(check_nonce(&k, peer(), &good, 1_000_000));
    }

    #[test]
    fn nonce_accepts_bounded_clock_skew_but_not_arbitrary_future() {
        // A peer server a second ahead must not produce a 438 loop; a nonce
        // dated an hour ahead is not a clock, it is a forgery attempt.
        let k = nonce_key(SECRET);
        let n = issue_nonce(&k, peer(), 1_000_000);
        assert!(check_nonce(&k, peer(), &n, 1_000_000 - NONCE_SKEW));
        assert!(!check_nonce(&k, peer(), &n, 1_000_000 - NONCE_SKEW - 1));
    }

    #[test]
    fn nonce_survives_the_u32_timestamp_rollover() {
        // The timestamp is serialised in 32 bits, so 2106-02-07 wraps. Comparing
        // in wrapping u32 space keeps a nonce issued just before the rollover
        // valid just after it, instead of failing every request for 600s.
        let k = nonce_key(SECRET);
        let before = u32::MAX as u64 - 10;
        let n = issue_nonce(&k, peer(), before);
        assert!(check_nonce(&k, peer(), &n, before));
        assert!(check_nonce(&k, peer(), &n, before + 20)); // past the wrap
        assert!(!check_nonce(&k, peer(), &n, before + NONCE_WINDOW + 2));
    }

    #[test]
    fn nonce_key_is_domain_separated_from_the_rest_secret() {
        // Two HMAC constructions under one key whose message spaces are not
        // provably disjoint is one parser quirk away from cross-protocol
        // forgery, so the nonce key is a derived, labelled key.
        let secret = "0123456789abcdef";
        let k = nonce_key(secret);
        assert_ne!(k.raw(), secret.as_bytes());
    }

    #[test]
    fn nonce_key_is_the_pinned_labelled_sha256() {
        // Pins the construction, not just that it differs from the secret: an
        // undetected change here silently invalidates every outstanding nonce
        // across a restart, and a dropped label would undo the separation the
        // test above claims to check.
        let k = nonce_key(SECRET);
        assert_eq!(
            hex(k.raw()),
            "648baf99c60f1e935948189153392319e8d225dad381b7d7d86a2db9ae8a5d64"
        );
        // Different secrets, different keys — and the NUL-terminated label means
        // no secret can be chosen to collide with the label itself.
        assert_ne!(hex(nonce_key("0123456789abcdeg").raw()), hex(k.raw()));
        // A nonce from one secret must never validate under another.
        let n = issue_nonce(&k, peer(), 1_000_000);
        assert!(!check_nonce(&nonce_key("fedcba9876543210"), peer(), &n, 1_000_000));
    }

    #[test]
    fn sha256_matches_the_fips_180_4_vectors() {
        // The inline hash exists only because `sha2` is not a dependency, so it
        // is pinned to published vectors. The 56-byte case is two blocks: it is
        // the one that catches a wrong padding boundary or a length field
        // appended in the wrong endianness.
        for (msg, want) in [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(hex(&sha256::digest(&[msg.as_bytes()])), want, "sha256({msg:?})");
        }
        // Multi-part input must hash as the concatenation, which is the only
        // property `nonce_key` relies on.
        assert_eq!(sha256::digest(&[b"ab", b"c"]), sha256::digest(&[b"abc"]));
    }

    #[test]
    fn nonce_is_fixed_width_lowercase_hex() {
        // `check_nonce` slices at fixed indices, so the issue side owes it a
        // fixed width; lowercase because the MAC covers the literal bytes.
        let k = nonce_key(SECRET);
        for now in [0u64, 1, 1_000_000, u32::MAX as u64] {
            let n = issue_nonce(&k, peer(), now);
            assert_eq!(n.len(), NONCE_LEN);
            assert!(n.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{n}");
            assert!(check_nonce(&k, peer(), &n, now));
        }
    }

    #[test]
    fn nonce_binds_v6_peers_distinctly() {
        // `SocketAddr`'s v6 Display brackets the address, so the ':' inside it
        // cannot be confused with the port separator. A v4-mapped address is a
        // different string from its v4 form, which is why turn.rs must
        // canonicalise before both issue and check.
        let k = nonce_key(SECRET);
        let v6: SocketAddr = "[2001:db8::1]:51000".parse().unwrap();
        let n = issue_nonce(&k, v6, 1_000_000);
        assert!(check_nonce(&k, v6, &n, 1_000_000));
        assert!(!check_nonce(&k, peer(), &n, 1_000_000));
        let mapped: SocketAddr = "[::ffff:203.0.113.9]:51000".parse().unwrap();
        assert!(!check_nonce(&k, mapped, &issue_nonce(&k, peer(), 1_000_000), 1_000_000));
    }

    #[test]
    fn realm_charset_is_enforced() {
        assert!(realm_is_valid("example.org"));
        assert!(!realm_is_valid(""));
        assert!(!realm_is_valid("has space"));
        assert!(!realm_is_valid("has\"quote"));
        assert!(!realm_is_valid("has\\backslash"));
        assert!(!realm_is_valid(&"x".repeat(128)));
        assert!(realm_is_valid(&"x".repeat(127)));
    }

    #[test]
    fn realm_rejects_the_rest_of_the_unsafe_set() {
        // The three coturn refuses beyond "not printable ASCII", plus the
        // whitespace and control characters that would break the attribute or
        // let a realm be smuggled into a log line.
        for bad in ["has'quote", "has\ttab", "has\rcr", "has\nlf", "has\0nul", "caf\u{e9}", "\u{7f}"]
        {
            assert!(!realm_is_valid(bad), "accepted {bad:?}");
        }
        // A 127-character realm is the RFC 8489 §14.9 maximum; measured in
        // bytes is the same as characters here because non-ASCII is refused.
        assert!(realm_is_valid("a"));
        assert!(realm_is_valid("turn.example.com:3478"));
    }
}
