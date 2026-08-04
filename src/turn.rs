//! TURN server (RFC 8656): listeners, dispatch, allocation lifecycle.
//!
//! This is the only module in the TURN group that touches the network. The
//! codec (`stun`), credentials (`turn_auth`) and allocation state
//! (`turn_alloc`) are pure and tested without a socket; the relayed transport
//! address lives in `turn_relay`, which deliberately cannot see the codec.
#![allow(dead_code)]

use crate::manager::{ConnEntry, Manager, ProxyRuntime};
use crate::model::TurnConfig;
use crate::stun::{self, Class, attr, method};
use crate::turn_alloc::{Channels, Permissions, PortPool};
use crate::turn_auth::{self, NonceKey};
use crate::turn_relay::RelaySocket;
use crate::turn_rrl::Rrl;
use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// REQUESTED-TRANSPORT value for UDP — the only relay transport we offer.
/// Anything else is 442 Unsupported Transport Protocol.
pub const TRANSPORT_UDP: u8 = 17;

/// REQUESTED-ADDRESS-FAMILY values (RFC 8656 §14.7 / RFC 6156).
pub const FAMILY_V4: u8 = 0x01;
pub const FAMILY_V6: u8 = 0x02;

/// How long a stream connection may stay open without creating an allocation.
/// `Manager::accept_loop` has no equivalent, and TURN's listeners bypass it, so
/// without this an attacker can park unauthenticated TCP/TLS connections.
pub const PRE_ALLOCATION_IDLE: std::time::Duration = std::time::Duration::from_secs(45);

/// Current wall clock in whole seconds.
pub fn now() -> u64 {
    (crate::model::now_ms() / 1000).max(0) as u64
}

/// Transport a client reached us over. `Tls` is a distinct value from `Tcp` for
/// 5-tuple keying (RFC 8656 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}

impl Transport {
    /// Whether ChannelData must be padded to a 4-byte boundary here
    /// (RFC 8656 §12.5).
    pub fn is_stream(self) -> bool {
        matches!(self, Transport::Tcp | Transport::Tls)
    }
}

/// The key an allocation is stored under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub transport: Transport,
}

/// Addresses this server must never relay to.
///
/// `Manager::is_internal_dest` cannot cover these: the host's own *public* IP is
/// not "internal", yet a permission pointing one allocation at another's relay
/// port makes a single injected packet circulate between two relay sockets
/// indefinitely — consuming CPU and bandwidth with no further attacker input,
/// and surviving the attacker disconnecting. A permission aimed at our own TURN
/// listener reaches our own parser; one aimed at the admin port reaches the
/// admin API from a source the operator may consider trusted.
pub struct SelfAddrs {
    ips: HashSet<IpAddr>,
    relay_range: (u16, u16),
    listeners: HashSet<SocketAddr>,
}

impl SelfAddrs {
    pub fn new(
        ips: HashSet<IpAddr>,
        relay_range: (u16, u16),
        listeners: HashSet<SocketAddr>,
    ) -> Self {
        Self {
            ips,
            relay_range,
            listeners,
        }
    }

    /// Whether `addr` is one of ours and therefore never a legal peer.
    pub fn contains(&self, addr: SocketAddr) -> bool {
        let ip = Manager::canonicalize_ip(addr.ip());
        if self.listeners.contains(&addr)
            || self.listeners.contains(&SocketAddr::new(ip, addr.port()))
        {
            return true;
        }
        self.is_own_relay(SocketAddr::new(ip, addr.port()))
    }

    /// Whether a datagram arriving on a relay socket came from one of our own
    /// relay ports — the backstop that breaks the loop even if a permission
    /// slipped through.
    pub fn is_own_relay(&self, addr: SocketAddr) -> bool {
        let ip = Manager::canonicalize_ip(addr.ip());
        self.ips.contains(&ip) && (self.relay_range.0..=self.relay_range.1).contains(&addr.port())
    }

    #[cfg(test)]
    pub fn for_test(ips: Vec<IpAddr>, range: (u16, u16), listeners: Vec<SocketAddr>) -> Self {
        Self::new(
            ips.into_iter().collect(),
            range,
            listeners.into_iter().collect(),
        )
    }
}

/// Blocklists pre-parsed into address types.
///
/// The datapath must not take `manager.blocklist`'s mutex or allocate a
/// `String` per packet: that mutex is shared across every proxy, so at media
/// rates the security check itself becomes the bottleneck and a TURN flood
/// stalls unrelated proxies. This snapshot is rebuilt when the config changes.
#[derive(Default)]
pub struct BlockSets {
    ips: HashSet<IpAddr>,
    socks: HashSet<SocketAddr>,
}

impl BlockSets {
    pub fn build(entries: impl Iterator<Item = String>) -> Self {
        let mut ips = HashSet::new();
        let mut socks = HashSet::new();
        for e in entries {
            let e = e.trim();
            if let Ok(sa) = e.parse::<SocketAddr>() {
                socks.insert(SocketAddr::new(Manager::canonicalize_ip(sa.ip()), sa.port()));
            } else if let Ok(ip) = e.parse::<IpAddr>() {
                ips.insert(Manager::canonicalize_ip(ip));
            }
        }
        Self { ips, socks }
    }

    /// Bare-IP match — the only granularity that can gate a permission, since
    /// permissions ignore the port by RFC mandate.
    pub fn blocks_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&Manager::canonicalize_ip(ip))
    }

    /// Full `ip:port` match, for the per-datagram check.
    pub fn blocks(&self, addr: SocketAddr) -> bool {
        let ip = Manager::canonicalize_ip(addr.ip());
        self.ips.contains(&ip) || self.socks.contains(&SocketAddr::new(ip, addr.port()))
    }
}

/// One live allocation.
pub struct Allocation {
    pub tuple: FiveTuple,
    /// Transaction id that created it, so a retransmitted Allocate can be told
    /// apart from a duplicate (RFC 8656 §7.2). Keying on the 5-tuple alone
    /// turns one lost response into a 437, which costs Chrome a full socket
    /// teardown and it only retries twice.
    pub txid: [u8; 12],
    /// Userid half of the REST username, for the 441 anti-hijack check and the
    /// per-user quota. Not the full username: its timestamp prefix rotates.
    pub userid: String,
    pub relay: Arc<RelaySocket>,
    pub port: u16,
    pub perms: Mutex<Permissions>,
    pub channels: Mutex<Channels>,
    pub expires: AtomicU64,
    pub entry: Arc<ConnEntry>,
    /// Datagrams refused by policy. Counted so a client hammering the server
    /// with denied traffic is visible instead of looking like an idle
    /// allocation.
    pub dropped: AtomicU64,
    /// Held for the allocation's life; releases the global cap on teardown.
    pub permit: Option<OwnedSemaphorePermit>,
}

impl Allocation {
    pub fn alive(&self, t: u64) -> bool {
        self.expires.load(Ordering::Relaxed) > t
    }
}

/// Shared state for one `Protocol::Turn` proxy.
pub struct Server {
    pub manager: Arc<Manager>,
    pub runtime: Arc<ProxyRuntime>,
    pub cfg: TurnConfig,
    pub realm: String,
    secret: String,
    pub nonce_key: NonceKey,
    pub max_lifetime: u64,
    pub ports: Mutex<PortPool>,
    pub allocations: DashMap<FiveTuple, Arc<Allocation>>,
    pub per_user: DashMap<String, usize>,
    pub alloc_sem: Arc<Semaphore>,
    pub conn_sem: Arc<Semaphore>,
    pub self_addrs: SelfAddrs,
    blocks: Mutex<Arc<BlockSets>>,
    pub rrl: Rrl,
    pub relay_ip: IpAddr,
    pub advertise_ip: Option<IpAddr>,
}

impl Server {
    /// Build the shared state, refusing configurations that cannot produce a
    /// working — or safe — server.
    pub fn new(manager: Arc<Manager>, runtime: Arc<ProxyRuntime>) -> Result<Arc<Self>> {
        let (cfg, listen_addr, blocklist, max_conns) = {
            let c = runtime.config.lock().unwrap();
            (
                c.turn.clone(),
                c.listen_addr.clone(),
                c.blocklist.clone(),
                crate::model::effective_max_connections(c.max_connections),
            )
        };

        // The last line of defence for the empty secret, after validate() and
        // before any bind. HMAC accepts a zero-length key without complaint, so
        // an unset secret would otherwise be an open relay handing out
        // correct-looking MESSAGE-INTEGRITY.
        let secret = cfg.static_secret.clone().unwrap_or_default();
        if secret.len() < turn_auth::MIN_SECRET_LEN {
            return Err(anyhow!(
                "turn needs a static_secret of at least {} bytes; refusing to start a relay that \
                 cannot authenticate anyone",
                turn_auth::MIN_SECRET_LEN
            ));
        }
        if !turn_auth::realm_is_valid(&cfg.realm) {
            return Err(anyhow!(
                "turn realm is empty or contains illegal characters (an empty realm makes \
                 libwebrtc compute MESSAGE-INTEGRITY over an empty key, which never authenticates)"
            ));
        }

        let listen: SocketAddr = listen_addr
            .parse()
            .map_err(|e| anyhow!("cannot parse listen address {listen_addr}: {e}"))?;

        // The relay socket must bind a concrete IP: a wildcard bind lets the
        // kernel choose a source per route, so a peer that probed relay IP A can
        // get the reply from IP B, discard it, and fail the ICE candidate pair
        // while a packet capture shows healthy traffic in both directions.
        let relay_ip = match cfg.relay_ip.as_deref() {
            Some(s) if !s.is_empty() => s
                .parse::<IpAddr>()
                .map_err(|e| anyhow!("invalid turn relay_ip {s}: {e}"))?,
            _ if !listen.ip().is_unspecified() => Manager::canonicalize_ip(listen.ip()),
            _ => {
                return Err(anyhow!(
                    "turn needs a concrete relay_ip when the listener binds a wildcard address"
                ));
            }
        };
        if relay_ip.is_unspecified() {
            return Err(anyhow!("turn relay_ip must not be a wildcard address"));
        }

        let advertise_ip = match cfg.advertise_ip.as_deref() {
            Some(s) if !s.is_empty() => Some(
                s.parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid turn advertise_ip {s}: {e}"))?,
            ),
            _ => None,
        };

        let (min_port, max_port) = cfg.effective_port_range();
        let pool = PortPool::new(min_port, max_port);
        let pool_capacity = pool.capacity();
        if pool_capacity == 0 {
            return Err(anyhow!(
                "turn relay port range {min_port}-{max_port} is empty"
            ));
        }

        // The allocation cap has to compose with the port range. `Some(0)` means
        // "unlimited" everywhere else in this codebase, but unlimited is not a
        // coherent setting for a relay that binds a socket per allocation, so it
        // is clamped to what the range can actually supply. Per the project's
        // permissive-with-warnings convention this warns rather than refuses.
        let cap = match max_conns {
            Some(n) => n.min(pool_capacity),
            None => {
                tracing::warn!(
                    "turn proxy has max_connections=0 (unlimited); clamping the allocation cap to \
                     the {pool_capacity}-port relay range, since every allocation binds a socket"
                );
                pool_capacity
            }
        };

        let mut listeners: HashSet<SocketAddr> = HashSet::new();
        listeners.insert(listen);
        if let Some(t) = cfg
            .tls_listen
            .as_deref()
            .and_then(|s| s.parse::<SocketAddr>().ok())
        {
            listeners.insert(t);
        }
        // Every other proxy's listener is off-limits as a peer too.
        for p in manager.proxies.iter() {
            if let Ok(a) = p
                .value()
                .config
                .lock()
                .unwrap()
                .listen_addr
                .parse::<SocketAddr>()
            {
                listeners.insert(a);
            }
        }

        let mut ips: HashSet<IpAddr> = HashSet::new();
        ips.insert(relay_ip);
        if let Some(a) = advertise_ip {
            ips.insert(a);
        }
        if !listen.ip().is_unspecified() {
            ips.insert(Manager::canonicalize_ip(listen.ip()));
        }

        Ok(Arc::new(Self {
            manager,
            runtime,
            realm: cfg.realm.clone(),
            nonce_key: turn_auth::nonce_key(&secret),
            max_lifetime: cfg.effective_max_lifetime(),
            secret,
            ports: Mutex::new(pool),
            allocations: DashMap::new(),
            per_user: DashMap::new(),
            alloc_sem: Arc::new(Semaphore::new(cap)),
            // Sized independently of the allocation cap: a stream connection is
            // much cheaper than an allocation, but still has to be bounded,
            // because TURN's listeners bypass accept_loop's semaphore entirely.
            conn_sem: Arc::new(Semaphore::new(cap.saturating_mul(4).max(64))),
            self_addrs: SelfAddrs::new(ips, (min_port, max_port), listeners),
            blocks: Mutex::new(Arc::new(BlockSets::build(blocklist.into_iter()))),
            rrl: Rrl::new(
                crate::turn_rrl::DEFAULT_BUCKETS,
                crate::turn_rrl::DEFAULT_RATE,
            ),
            relay_ip,
            advertise_ip,
            cfg,
        }))
    }

    /// The current pre-parsed blocklist snapshot.
    pub fn blocks(&self) -> Arc<BlockSets> {
        self.blocks.lock().unwrap().clone()
    }

    /// Rebuild the blocklist snapshot from the live config. Called off the
    /// datapath, on config change.
    pub fn refresh_blocks(&self) {
        let list = self.runtime.config.lock().unwrap().blocklist.clone();
        let mut mgr: Vec<String> = self
            .manager
            .blocklist
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        mgr.extend(list);
        *self.blocks.lock().unwrap() = Arc::new(BlockSets::build(mgr.into_iter()));
    }

    /// The address advertised in XOR-RELAYED-ADDRESS for a bound relay port.
    pub fn advertised(&self, bound: SocketAddr) -> SocketAddr {
        match self.advertise_ip {
            Some(ip) => SocketAddr::new(ip, bound.port()),
            None => bound,
        }
    }

    /// Whether a peer address may be permissioned at all, and the RFC error to
    /// answer with when it may not.
    ///
    /// 403 is the right refusal, not 401 (libwebrtc treats a second 401 as a
    /// terminal credential failure and destroys the port) and not silence
    /// (which burns the whole STUN retransmission budget before timing out).
    /// This fires on a large fraction of real calls, because Chrome asks for
    /// permission on the remote peer's RFC1918 host candidates every time.
    pub fn peer_rejection(&self, peer: SocketAddr) -> Option<u16> {
        if peer.port() == 0 {
            return Some(400);
        }
        let ip = Manager::canonicalize_ip(peer.ip());
        if !self.cfg.allow_private && Manager::is_internal_dest(ip) {
            return Some(403);
        }
        if self.self_addrs.contains(SocketAddr::new(ip, peer.port())) {
            return Some(403);
        }
        if self.blocks().blocks_ip(ip) {
            return Some(403);
        }
        None
    }

    /// Per-datagram check on the outbound path. Stricter in one way than
    /// [`Self::peer_rejection`]: a full `ip:port` blocklist entry bites here,
    /// where it cannot gate a permission (permissions are keyed on IP only, a
    /// MUST, so an operator blocklisting `1.2.3.4:25` would otherwise see the
    /// permission accepted).
    pub fn peer_send_allowed(&self, peer: SocketAddr) -> bool {
        self.peer_rejection(peer).is_none() && !self.blocks().blocks(peer)
    }
}

/// Where a response goes: abstracts "write back to this client" over the
/// datagram and stream listeners.
#[derive(Clone)]
pub enum Reply {
    Udp {
        sock: Arc<UdpSocket>,
        to: SocketAddr,
    },
    Stream(Arc<StreamWriter>),
}

/// A stream client's write half behind a mutex, so two relay tasks can never
/// interleave halves of two frames onto one connection.
pub struct StreamWriter {
    inner: tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl StreamWriter {
    pub fn new(w: Box<dyn AsyncWrite + Send + Unpin>) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(w),
        }
    }

    async fn write_frame(&self, frame: &[u8]) -> std::io::Result<()> {
        let mut g = self.inner.lock().await;
        g.write_all(frame).await?;
        g.flush().await
    }
}

impl Reply {
    pub async fn send(&self, frame: &[u8]) {
        match self {
            Reply::Udp { sock, to } => {
                if let Err(e) = sock.send_to(frame, *to).await {
                    tracing::debug!("turn: reply to {to} failed: {e}");
                }
            }
            Reply::Stream(w) => {
                if let Err(e) = w.write_frame(frame).await {
                    tracing::debug!("turn: stream reply failed: {e}");
                }
            }
        }
    }
}

/// On-wire size of a ChannelData frame carrying `len` payload bytes over a
/// stream transport.
///
/// RFC 8656 §12.5 requires the padding, and libwebrtc's `AsyncStunTCPSocket`
/// consumes exactly this many bytes. An unpadded frame makes the client swallow
/// up to three bytes of the next message as padding — and a byte stream has no
/// resynchronisation point, so every later frame on that connection is
/// misparsed for good.
pub fn pad_channel_data(len: usize) -> usize {
    (4 + len).div_ceil(4) * 4
}

/// Total length of the frame starting at `head`, or `None` when the first byte
/// is not something we can frame (RFC 7983 demux via RFC 8656 Table 3).
pub fn frame_len(head: &[u8]) -> Option<usize> {
    if head.len() < 4 {
        return None;
    }
    let declared = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] {
        0..=3 => Some(stun::HEADER_LEN + declared),
        64..=79 => Some(pad_channel_data(declared)),
        _ => None,
    }
}

/// Build a ChannelData frame for `payload`.
pub fn channel_data(num: u16, payload: &[u8], transport: Transport) -> Vec<u8> {
    let mut out = Vec::with_capacity(pad_channel_data(payload.len()));
    out.extend_from_slice(&num.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    if transport.is_stream() {
        out.resize(pad_channel_data(payload.len()), 0);
    }
    out
}

/// A 401 or 438 challenge.
///
/// Both codes come from one emitter on purpose. libwebrtc's `UpdateNonce()`
/// logs "Missing STUN_ATTR_REALM attribute in stale nonce error response" and
/// returns **without retrying** when REALM is absent, so a 438 built separately
/// from the 401 turns routine nonce rotation into a dead allocation with no
/// error surfaced to the application. The challenge is itself unauthenticated —
/// RFC 8489 §9.2.4 says it SHOULD NOT carry MESSAGE-INTEGRITY.
pub fn challenge(code: u16, realm: &str, nonce: &str, txid: [u8; 12], m: u16) -> Option<Vec<u8>> {
    let mut b = stun::Builder::new(m, Class::Error, txid);
    b.push_error(
        code,
        if code == 401 {
            "Unauthenticated"
        } else {
            "Stale Nonce"
        },
    );
    b.push(attr::REALM, realm.as_bytes());
    b.push(attr::NONCE, nonce.as_bytes());
    b.finish(None, false)
}

/// An error response, signed when the request authenticated.
pub fn error_response(
    code: u16,
    reason: &str,
    txid: [u8; 12],
    m: u16,
    key: Option<&[u8]>,
    fingerprint: bool,
    unknown: &[u16],
) -> Option<Vec<u8>> {
    let mut b = stun::Builder::new(m, Class::Error, txid);
    b.push_error(code, reason);
    if !unknown.is_empty() {
        b.push_unknown_attributes(unknown);
    }
    b.finish(key, fingerprint)
}

/// A Binding success response.
///
/// Answered **unauthenticated, before any allocation lookup**. libwebrtc shares
/// one UDP socket between its `UDPPort` and `TurnPort` whenever the TURN address
/// is also in the STUN server set — the default — so a plain Binding arrives on
/// the exact same 5-tuple as the Allocate. Answering it with 437, 441 or a 401
/// challenge costs Chrome its server-reflexive candidate and pushes traffic onto
/// the relay, the opposite of what an operator wants.
pub fn binding_response(txid: [u8; 12], client: SocketAddr, fingerprint: bool) -> Option<Vec<u8>> {
    let mut b = stun::Builder::new(method::BINDING, Class::Success, txid);
    b.push_xor_addr(attr::XOR_MAPPED_ADDRESS, client);
    b.finish(None, fingerprint)
}

/// An Allocate success response.
pub fn allocate_success(
    txid: [u8; 12],
    relayed: SocketAddr,
    client: SocketAddr,
    lifetime: u64,
    key: Option<&[u8]>,
    fingerprint: bool,
) -> Option<Vec<u8>> {
    let mut b = stun::Builder::new(method::ALLOCATE, Class::Success, txid);
    b.push_xor_addr(attr::XOR_RELAYED_ADDRESS, relayed);
    b.push_u32(attr::LIFETIME, lifetime.min(u32::MAX as u64) as u32);
    // Always the client's observed address from the 5-tuple, never advertise_ip.
    b.push_xor_addr(attr::XOR_MAPPED_ADDRESS, client);
    b.finish(key, fingerprint)
}

/// A Refresh success response, echoing the granted lifetime.
pub fn refresh_success(
    txid: [u8; 12],
    lifetime: u64,
    key: Option<&[u8]>,
    fingerprint: bool,
) -> Option<Vec<u8>> {
    let mut b = stun::Builder::new(method::REFRESH, Class::Success, txid);
    b.push_u32(attr::LIFETIME, lifetime.min(u32::MAX as u64) as u32);
    b.finish(key, fingerprint)
}

/// A bare success response (CreatePermission / ChannelBind carry no required
/// attributes, but must still be signed).
pub fn bare_success(
    m: u16,
    txid: [u8; 12],
    key: Option<&[u8]>,
    fingerprint: bool,
) -> Option<Vec<u8>> {
    stun::Builder::new(m, Class::Success, txid).finish(key, fingerprint)
}

/// A Data indication wrapping one relayed datagram.
pub fn data_indication(peer: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut txid = [0u8; 12];
    // Indications are unmatched, so the transaction id only has to be unique
    // enough not to confuse a client's demultiplexer.
    let _ = getrandom::fill(&mut txid);
    let mut b = stun::Builder::new(method::DATA, Class::Indication, txid);
    b.push_xor_addr(attr::XOR_PEER_ADDRESS, peer);
    b.push(attr::DATA, payload);
    b.finish(None, false)
}

#[cfg(test)]
fn error_code_of(m: &stun::Message<'_>) -> Option<u16> {
    let v = stun::first(m, attr::ERROR_CODE)?;
    (v.len() >= 4).then(|| v[2] as u16 * 100 + v[3] as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turn_alloc::{RefreshOutcome, refresh_lifetime};

    #[test]
    fn channel_data_is_padded_to_four_on_streams() {
        // libwebrtc consumes exactly ((4 + len + 3) & ~3) bytes; an unpadded
        // frame desynchronises the connection permanently.
        assert_eq!(pad_channel_data(0), 4);
        assert_eq!(pad_channel_data(1), 8);
        assert_eq!(pad_channel_data(2), 8);
        assert_eq!(pad_channel_data(3), 8);
        assert_eq!(pad_channel_data(4), 8);
        assert_eq!(pad_channel_data(5), 12);

        for len in 1..=3usize {
            let f = channel_data(0x4001, &vec![7u8; len], Transport::Tcp);
            assert_eq!(
                f.len(),
                8,
                "{len}-byte payload must occupy 8 bytes on a stream"
            );
            assert_eq!(
                u16::from_be_bytes([f[2], f[3]]) as usize,
                len,
                "the declared length excludes padding"
            );
        }
        // Over UDP padding is not required, so the frame stays tight.
        assert_eq!(channel_data(0x4001, &[7u8; 1], Transport::Udp).len(), 5);
    }

    #[test]
    fn frame_len_reads_stun_and_channel_data() {
        let mut head = vec![0x00, 0x01, 0x00, 0x58];
        head.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        assert_eq!(frame_len(&head), Some(20 + 0x58));
        assert_eq!(frame_len(&[0x40, 0x01, 0x00, 0x05]), Some(12));
        assert_eq!(frame_len(&[0x4F, 0x01, 0x00, 0x00]), Some(4));
        // Anything else on a stream is unframeable: drop the connection rather
        // than guess where the next message begins.
        assert_eq!(frame_len(&[0x16, 0x00, 0x00, 0x00]), None); // DTLS
        assert_eq!(frame_len(&[0x80, 0x00, 0x00, 0x00]), None); // RTP
        assert_eq!(frame_len(&[0x00, 0x01]), None); // short
    }

    #[test]
    fn challenge_carries_realm_and_nonce_and_is_unsigned() {
        for (code, m) in [(401u16, method::ALLOCATE), (438, method::REFRESH)] {
            let out = challenge(code, "example.org", "abcd1234", [1u8; 12], m).unwrap();
            let msg = stun::parse(&out).unwrap();
            assert_eq!(msg.class, Class::Error);
            assert_eq!(error_code_of(&msg), Some(code));
            assert_eq!(stun::first(&msg, attr::REALM).unwrap(), b"example.org");
            assert_eq!(stun::first(&msg, attr::NONCE).unwrap(), b"abcd1234");
            // Signing the challenge is explicitly wrong: the client has no key
            // for it yet, and RFC 8489 9.2.4 says SHOULD NOT.
            assert!(msg.mi_offset.is_none());
        }
    }

    #[test]
    fn binding_is_answered_unauthenticated_with_the_observed_address() {
        let peer: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let out = binding_response([3u8; 12], peer, false).unwrap();
        let m = stun::parse(&out).unwrap();
        assert_eq!(m.class, Class::Success);
        assert_eq!(m.method, method::BINDING);
        assert!(m.mi_offset.is_none());
        let v = stun::first(&m, attr::XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(stun::parse_xor_addr(&m.txid, v).unwrap(), peer);
    }

    #[test]
    fn authenticated_responses_are_signed() {
        // RFC 8489 9.2.4 makes this a MUST. Chrome never verifies it, so
        // without an explicit check an unsigned server passes every browser
        // test and then fails Firefox and aiortc in production.
        let key = [4u8; 16];
        let relayed: SocketAddr = "198.51.100.4:50100".parse().unwrap();
        let client: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let out = allocate_success([5u8; 12], relayed, client, 600, Some(&key), false).unwrap();
        let m = stun::parse(&out).unwrap();
        let mi = m.mi_offset.expect("post-auth responses MUST be signed");
        assert!(stun::verify_integrity(&out, mi, &key));
        let r = stun::first(&m, attr::XOR_RELAYED_ADDRESS).unwrap();
        assert_eq!(stun::parse_xor_addr(&m.txid, r).unwrap(), relayed);
        let c = stun::first(&m, attr::XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(stun::parse_xor_addr(&m.txid, c).unwrap(), client);
        assert_eq!(
            stun::first(&m, attr::LIFETIME).unwrap(),
            &600u32.to_be_bytes()
        );

        for out in [
            refresh_success([6u8; 12], 600, Some(&key), false).unwrap(),
            bare_success(method::CREATE_PERMISSION, [7u8; 12], Some(&key), false).unwrap(),
            bare_success(method::CHANNEL_BIND, [8u8; 12], Some(&key), false).unwrap(),
            error_response(438, "Stale Nonce", [9u8; 12], method::REFRESH, Some(&key), false, &[])
                .unwrap(),
        ] {
            let m = stun::parse(&out).unwrap();
            let mi = m.mi_offset.expect("every post-auth response is signed");
            assert!(stun::verify_integrity(&out, mi, &key));
        }
    }

    #[test]
    fn refresh_zero_is_delete_and_anything_else_is_clamped() {
        // TurnPort::Release() sends LIFETIME=0 and branches on the ECHOED
        // value; answering 600 leaks an allocation and a relay port per call.
        assert_eq!(refresh_lifetime(Some(0), 3600), RefreshOutcome::Delete);
        assert_eq!(refresh_lifetime(Some(60), 3600), RefreshOutcome::Keep(600));
        assert_eq!(refresh_lifetime(None, 3600), RefreshOutcome::Keep(600));
        let out = refresh_success([1u8; 12], 0, None, false).unwrap();
        let m = stun::parse(&out).unwrap();
        assert_eq!(stun::first(&m, attr::LIFETIME).unwrap(), &0u32.to_be_bytes());
    }

    #[test]
    fn unknown_comprehension_required_yields_420_with_the_list() {
        let out = error_response(
            420,
            "Unknown Attribute",
            [6u8; 12],
            method::ALLOCATE,
            None,
            false,
            &[attr::EVEN_PORT, attr::RESERVATION_TOKEN],
        )
        .unwrap();
        let m = stun::parse(&out).unwrap();
        assert_eq!(error_code_of(&m), Some(420));
        assert_eq!(
            stun::first(&m, attr::UNKNOWN_ATTRIBUTES).unwrap(),
            &[0x00, 0x18, 0x00, 0x22]
        );
    }

    #[test]
    fn data_indication_carries_peer_and_payload_unsigned() {
        // Indications are never signed, and the payload crosses verbatim.
        let peer: SocketAddr = "203.0.113.9:9000".parse().unwrap();
        let payload = b"\x16\xfe\xfd dtls-looking bytes";
        let out = data_indication(peer, payload).unwrap();
        let m = stun::parse(&out).unwrap();
        assert_eq!(m.class, Class::Indication);
        assert_eq!(m.method, method::DATA);
        assert!(m.mi_offset.is_none());
        let p = stun::first(&m, attr::XOR_PEER_ADDRESS).unwrap();
        assert_eq!(stun::parse_xor_addr(&m.txid, p).unwrap(), peer);
        assert_eq!(stun::first(&m, attr::DATA).unwrap(), payload);
    }

    #[test]
    fn self_addresses_block_the_relay_loop() {
        // is_internal_dest cannot help: our own PUBLIC IP is not "internal",
        // yet a permission aimed at another allocation's relay port makes one
        // injected packet circulate between two relay sockets indefinitely.
        let s = SelfAddrs::for_test(
            vec!["198.51.100.4".parse().unwrap()],
            (49152, 51199),
            vec![
                "198.51.100.4:3478".parse().unwrap(),
                "198.51.100.4:8080".parse().unwrap(),
            ],
        );
        assert!(s.contains("198.51.100.4:50000".parse().unwrap()), "our relay range");
        assert!(s.contains("198.51.100.4:3478".parse().unwrap()), "our TURN listener");
        assert!(s.contains("198.51.100.4:8080".parse().unwrap()), "the admin port");
        assert!(!s.contains("198.51.100.4:443".parse().unwrap()));
        assert!(!s.contains("203.0.113.9:50000".parse().unwrap()));
        assert!(s.is_own_relay("198.51.100.4:49152".parse().unwrap()));
        assert!(!s.is_own_relay("198.51.100.4:80".parse().unwrap()));
    }

    #[test]
    fn blocksets_match_at_the_right_layer_for_each_check() {
        let b = BlockSets::build(["1.2.3.4".to_string(), "5.6.7.8:25".to_string()].into_iter());
        // A bare IP gates a permission (permissions are IP-only, a MUST).
        assert!(b.blocks_ip("1.2.3.4".parse().unwrap()));
        // An ip:port entry cannot gate a permission...
        assert!(!b.blocks_ip("5.6.7.8".parse().unwrap()));
        // ...but still bites per datagram, which is why there are two checks.
        assert!(b.blocks("5.6.7.8:25".parse().unwrap()));
        assert!(!b.blocks("5.6.7.8:80".parse().unwrap()));
        // v4-mapped v6 is canonicalised, so it cannot be used to slip past.
        assert!(b.blocks_ip("::ffff:1.2.3.4".parse().unwrap()));
    }
}
