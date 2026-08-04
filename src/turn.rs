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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

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
    /// Where peer traffic is written back to this client.
    pub reply: Reply,
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
        .inspect(|s| {
            tracing::debug!(
                "turn: allocation cap {cap}, relay {min_port}-{max_port} on {relay_ip}, \
                 {} rate-limit buckets",
                s.rrl.footprint()
            );
        })
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
        // Port 0 is only meaningless where the port is actually used as a
        // destination — ChannelBind and the outbound datapath. CreatePermission
        // goes through `peer_ip_rejection`, because RFC 8656 §9.2 ignores the
        // port there outright and a client is entitled to send zero.
        if peer.port() == 0 {
            return Some(400);
        }
        self.peer_ip_rejection(peer.ip())
            .or_else(|| self.self_addrs.contains(peer).then_some(403))
    }

    /// Policy check on a peer's IP alone — the granularity a permission uses.
    pub fn peer_ip_rejection(&self, ip: IpAddr) -> Option<u16> {
        let ip = Manager::canonicalize_ip(ip);
        if !self.cfg.allow_private && Manager::is_internal_dest(ip) {
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

/// Outcome of the long-term credential check.
enum Auth {
    Ok {
        key: [u8; 16],
        userid: String,
    },
    /// 401 Unauthenticated or 438 Stale Nonce — both answered with a fresh
    /// challenge.
    Challenge(u16),
    /// MESSAGE-INTEGRITY present but USERNAME/REALM/NONCE missing. RFC 8489
    /// §9.2.4 wants a 400 here, and it must not carry any of those attributes.
    BadRequest,
}

/// Verify a request's long-term credentials.
///
/// The check order is normative (RFC 8489 §9.2.4) and not interchangeable:
/// testing the nonce before the HMAC would let an unauthenticated attacker
/// probe nonce validity, and would answer 438 where the RFC wants 401.
fn authenticate(srv: &Server, m: &stun::Message<'_>, client: SocketAddr, t: u64) -> Auth {
    let Some(mi) = m.mi_offset else {
        return Auth::Challenge(401);
    };
    let (Some(user), Some(realm), Some(nonce)) = (
        stun::first(m, attr::USERNAME),
        stun::first(m, attr::REALM),
        stun::first(m, attr::NONCE),
    ) else {
        return Auth::BadRequest;
    };
    let (Ok(user), Ok(realm), Ok(nonce)) = (
        std::str::from_utf8(user),
        std::str::from_utf8(realm),
        std::str::from_utf8(nonce),
    ) else {
        return Auth::BadRequest;
    };

    // The client echoes back whatever realm we sent; the key derivation must
    // use the same bytes, so a mismatch can never authenticate.
    let cred = match turn_auth::parse_username(user, t, srv.cfg.effective_horizon()) {
        Ok(c) => c,
        Err(_) => return Auth::Challenge(401),
    };
    let key = match turn_auth::credential_key(&srv.secret, user, realm) {
        Ok(k) => k,
        Err(_) => return Auth::Challenge(401),
    };
    if !stun::verify_integrity(m.raw, mi, &key) {
        return Auth::Challenge(401);
    }
    // Only once the HMAC verifies does nonce freshness become the client's
    // problem to fix.
    if !turn_auth::check_nonce(&srv.nonce_key, client, nonce, t) {
        return Auth::Challenge(438);
    }
    Auth::Ok {
        key,
        userid: cred.userid,
    }
}

/// Address family of a peer address, as RFC 6156 numbers it.
fn family_of(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => FAMILY_V4,
        IpAddr::V6(_) => FAMILY_V6,
    }
}

/// Tear an allocation down: cascade to permissions, channels and the relay
/// socket, return the port, release the cap permit, and write history.
///
/// Single owner, mirroring the UDP forwarder: every exit cause converges on
/// cancelling the `ConnEntry` token, which ends the relay task, which runs this
/// exactly once. The 5-tuple is freed immediately so a re-Allocate from the same
/// source port succeeds instead of hitting 437.
fn teardown(srv: &Arc<Server>, tuple: &FiveTuple) {
    let Some((_, alloc)) = srv.allocations.remove(tuple) else {
        return;
    };
    srv.ports.lock().unwrap().give(alloc.port);
    if let Some(mut n) = srv.per_user.get_mut(&alloc.userid) {
        *n = n.saturating_sub(1);
    }
    srv.per_user.remove_if(&alloc.userid, |_, n| *n == 0);

    // Allocations that relayed nothing and lived briefly are not recorded. An
    // Allocate/Refresh(0) loop is a single round trip, so writing a row per
    // cycle would let one credential fill the disk — and when RocksDB's
    // filesystem fills, the config store goes with it.
    let moved = alloc.entry.bytes_sent.load(Ordering::Relaxed)
        + alloc.entry.bytes_received.load(Ordering::Relaxed);
    let lived = crate::model::now_ms() - alloc.entry.started_at;
    if moved > 0 || lived > 5_000 {
        crate::relay::udp_session_end(&srv.manager.storage, &srv.runtime, &alloc.entry);
    } else {
        srv.runtime.conns.remove(&alloc.entry.id);
    }
}

/// Per-allocation relay reader: peer → client.
///
/// The single owner of teardown for this allocation.
async fn relay_task(srv: Arc<Server>, tuple: FiveTuple, alloc: Arc<Allocation>) {
    let mut buf = vec![0u8; srv.cfg.effective_max_datagram()];
    let cancel = alloc.entry.cancel.clone();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = alloc.relay.recv_from(&mut buf) => {
                let (n, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("turn: relay recv for {} ended: {e}", tuple.client);
                        break;
                    }
                };
                let t = now();
                if !alloc.alive(t) {
                    break;
                }
                // Break the amplification loop even if a permission slipped
                // through: a datagram whose SOURCE is one of our own relay
                // ports is either a loop or a spoof, never real peer traffic.
                if srv.self_addrs.is_own_relay(peer) {
                    alloc.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let permitted = alloc.perms.lock().unwrap().allowed(peer.ip(), t);
                if !permitted || !srv.peer_send_allowed(peer) {
                    alloc.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // ChannelData when a channel is bound to this peer, a Data
                // indication otherwise (RFC 8656 §11.3 / §12.6).
                let bound = alloc.channels.lock().unwrap().num_of(peer, t);
                let frame = match bound {
                    Some(num) => Some(channel_data(num, &buf[..n], tuple.transport)),
                    None => data_indication(peer, &buf[..n]),
                };
                if let Some(f) = frame {
                    alloc.reply.send(&f).await;
                    alloc.entry.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    }
    teardown(&srv, &tuple);
}

/// Handle one client message. See the module docs for why the order is fixed.
pub async fn handle_message(srv: &Arc<Server>, tuple: FiveTuple, buf: &[u8], reply: &Reply) {
    // 1. Demux on the first byte (RFC 7983 via RFC 8656 Table 3).
    match buf.first().copied() {
        Some(0..=3) => {}
        Some(64..=79) => {
            handle_channel_data(srv, tuple, buf).await;
            return;
        }
        // Never answer garbage: on UDP a response to an unparseable datagram
        // is a free reflection primitive.
        _ => return,
    }

    let Some(m) = stun::parse(buf) else { return };
    let t = now();

    // 2. Binding is answered immediately, unauthenticated, before any
    //    allocation lookup. Chrome shares one socket between its UDPPort and
    //    TurnPort, so a plain Binding arrives on the same 5-tuple as the
    //    Allocate; a 401/437/441 here costs it the srflx candidate.
    if m.method == method::BINDING {
        if m.class == Class::Request
            && srv.rrl.allow_at(tuple.client.ip(), t as u32)
            && let Some(out) = binding_response(m.txid, tuple.client, m.has_fingerprint)
        {
            reply.send(&out).await;
        }
        return;
    }

    // 3. Indications are never answered and never authenticated.
    if m.class == Class::Indication {
        if m.method == method::SEND {
            handle_send(srv, tuple, &m).await;
        }
        return;
    }
    if m.class != Class::Request {
        return;
    }

    // 4. Long-term credentials, in the RFC's order.
    let (key, userid) = match authenticate(srv, &m, tuple.client, t) {
        Auth::Ok { key, userid } => (key, userid),
        Auth::BadRequest => {
            if srv.rrl.allow_at(tuple.client.ip(), t as u32)
                && let Some(out) =
                    error_response(400, "Bad Request", m.txid, m.method, None, m.has_fingerprint, &[])
            {
                reply.send(&out).await;
            }
            return;
        }
        Auth::Challenge(code) => {
            // The mandatory challenge is an unauthenticated response, i.e. a
            // reflection amplifier by construction — rate limit it.
            if srv.rrl.allow_at(tuple.client.ip(), t as u32) {
                let nonce = turn_auth::issue_nonce(&srv.nonce_key, tuple.client, t);
                if let Some(out) = challenge(code, &srv.realm, &nonce, m.txid, m.method) {
                    reply.send(&out).await;
                }
            }
            return;
        }
    };

    // 5. Unknown comprehension-required attributes, now that we can sign the
    //    answer. EVEN-PORT and RESERVATION-TOKEN land here by design: 420 is
    //    the RFC-prescribed way to say "unsupported" and clients retry without.
    if !m.unknown_required.is_empty() {
        if let Some(out) = error_response(
            420,
            "Unknown Attribute",
            m.txid,
            m.method,
            Some(&key),
            m.has_fingerprint,
            &m.unknown_required,
        ) {
            reply.send(&out).await;
        }
        return;
    }

    if m.method == method::ALLOCATE {
        handle_allocate(srv, tuple, &m, &key, &userid, reply).await;
        return;
    }

    // 6. Every other request needs an existing allocation on this 5-tuple.
    let Some(alloc) = srv.allocations.get(&tuple).map(|a| a.clone()) else {
        if let Some(out) = error_response(
            437,
            "Allocation Mismatch",
            m.txid,
            m.method,
            Some(&key),
            m.has_fingerprint,
            &[],
        ) {
            reply.send(&out).await;
        }
        return;
    };

    // 7. Anti-hijack: the same credential that created the allocation must be
    //    the one refreshing it. Compared on the USERID half only — the REST
    //    timestamp prefix rotates, so comparing the full username would kill
    //    live allocations for any client that re-derives credentials.
    if alloc.userid != userid {
        if let Some(out) = error_response(
            441,
            "Wrong Credentials",
            m.txid,
            m.method,
            Some(&key),
            m.has_fingerprint,
            &[],
        ) {
            reply.send(&out).await;
        }
        return;
    }

    match m.method {
        method::REFRESH => handle_refresh(srv, tuple, &m, &alloc, &key, reply).await,
        method::CREATE_PERMISSION => handle_create_permission(srv, &m, &alloc, &key, reply).await,
        method::CHANNEL_BIND => handle_channel_bind(srv, &m, &alloc, &key, reply).await,
        _ => {
            if let Some(out) = error_response(
                400,
                "Bad Request",
                m.txid,
                m.method,
                Some(&key),
                m.has_fingerprint,
                &[],
            ) {
                reply.send(&out).await;
            }
        }
    }
}

async fn handle_allocate(
    srv: &Arc<Server>,
    tuple: FiveTuple,
    m: &stun::Message<'_>,
    key: &[u8; 16],
    userid: &str,
    reply: &Reply,
) {
    let t = now();
    let fp = m.has_fingerprint;
    let fail = |code: u16, reason: &'static str| {
        error_response(code, reason, m.txid, method::ALLOCATE, Some(key), fp, &[])
    };

    // A retransmitted Allocate (same 5-tuple AND same transaction id) replays
    // the success response. Treating it as a duplicate instead would make one
    // lost response cost Chrome a full socket teardown, and it only retries
    // twice before giving up on relay gathering entirely.
    if let Some(existing) = srv.allocations.get(&tuple).map(|a| a.clone()) {
        if existing.txid == m.txid {
            let remaining = existing.expires.load(Ordering::Relaxed).saturating_sub(t);
            if let Some(out) = allocate_success(
                m.txid,
                existing.relay.advertised(),
                tuple.client,
                remaining,
                Some(key),
                fp,
            ) {
                reply.send(&out).await;
            }
        } else if let Some(out) = fail(437, "Allocation Mismatch") {
            reply.send(&out).await;
        }
        return;
    }

    // REQUESTED-TRANSPORT is mandatory; only UDP relays are offered.
    match stun::first(m, attr::REQUESTED_TRANSPORT) {
        Some(v) if v.len() == 4 && v[0] == TRANSPORT_UDP => {}
        Some(v) if v.len() == 4 => {
            if let Some(out) = fail(442, "Unsupported Transport Protocol") {
                reply.send(&out).await;
            }
            return;
        }
        _ => {
            if let Some(out) = fail(400, "Bad Request") {
                reply.send(&out).await;
            }
            return;
        }
    }

    // RFC 6156 address family. Absent means IPv4.
    let want_family = match stun::first(m, attr::REQUESTED_ADDRESS_FAMILY) {
        None => FAMILY_V4,
        Some(v) if v.len() == 4 && (v[0] == FAMILY_V4 || v[0] == FAMILY_V6) => v[0],
        Some(_) => {
            if let Some(out) = fail(400, "Bad Request") {
                reply.send(&out).await;
            }
            return;
        }
    };
    if want_family != family_of(srv.relay_ip) {
        // The client MUST NOT retry after 440, so this is the honest answer
        // when the configured relay IP is the other family.
        if let Some(out) = fail(440, "Address Family not Supported") {
            reply.send(&out).await;
        }
        return;
    }

    // Per-user quota, keyed on the userid rather than the rotating username.
    let per_user = srv.cfg.effective_per_user();
    {
        let count = srv.per_user.get(userid).map(|n| *n).unwrap_or(0);
        if count >= per_user {
            if let Some(out) = fail(486, "Allocation Quota Reached") {
                reply.send(&out).await;
            }
            return;
        }
    }

    // Global cap. 486 and 508 are the codes for transient exhaustion — never
    // 401, which libwebrtc treats as a terminal credential failure and which
    // would make the browser give up on this server entirely.
    let Ok(permit) = srv.alloc_sem.clone().try_acquire_owned() else {
        if let Some(out) = fail(486, "Allocation Quota Reached") {
            reply.send(&out).await;
        }
        return;
    };

    let Some(port) = srv.ports.lock().unwrap().take() else {
        if let Some(out) = fail(508, "Insufficient Capacity") {
            reply.send(&out).await;
        }
        return;
    };

    let (sock, bound) = match crate::turn_relay::bind_relay(srv.relay_ip, port).await {
        Ok(v) => v,
        Err(e) => {
            // EMFILE and friends are capacity, not a client error, and must not
            // be retried into a syscall storm.
            tracing::debug!("turn: relay bind on port {port} failed: {e}");
            srv.ports.lock().unwrap().give(port);
            if let Some(out) = fail(508, "Insufficient Capacity") {
                reply.send(&out).await;
            }
            return;
        }
    };
    let advertised = srv.advertised(bound);
    let relay = Arc::new(RelaySocket::new(sock, bound, advertised));
    if relay.bound() != advertised {
        // Under 1:1 NAT these differ, and a mismatch between what we bound and
        // what we advertise is the first thing to check when ICE fails.
        tracing::debug!(
            "turn: allocation for {} relays on {} advertised as {advertised}",
            tuple.client,
            relay.bound()
        );
    }

    let lifetime = crate::turn_alloc::granted_lifetime(
        stun::first(m, attr::LIFETIME)
            .filter(|v| v.len() == 4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        srv.max_lifetime,
    );

    let entry = crate::relay::udp_session_start(
        &srv.runtime,
        tuple.client.to_string(),
        advertised.to_string(),
    );

    let alloc = Arc::new(Allocation {
        tuple,
        txid: m.txid,
        userid: userid.to_string(),
        relay,
        port,
        perms: Mutex::new(Permissions::new(srv.cfg.effective_max_permissions())),
        channels: Mutex::new(Channels::new(srv.cfg.effective_max_channels())),
        expires: AtomicU64::new(t + lifetime),
        entry,
        dropped: AtomicU64::new(0),
        permit: Some(permit),
        reply: reply.clone(),
    });
    srv.allocations.insert(tuple, alloc.clone());
    *srv.per_user.entry(userid.to_string()).or_insert(0) += 1;

    let s = srv.clone();
    let a = alloc.clone();
    tokio::spawn(async move { relay_task(s, tuple, a).await });

    if let Some(out) = allocate_success(m.txid, advertised, tuple.client, lifetime, Some(key), fp) {
        reply.send(&out).await;
    }
}

async fn handle_refresh(
    srv: &Arc<Server>,
    tuple: FiveTuple,
    m: &stun::Message<'_>,
    alloc: &Arc<Allocation>,
    key: &[u8; 16],
    reply: &Reply,
) {
    let requested = stun::first(m, attr::LIFETIME)
        .filter(|v| v.len() == 4)
        .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));

    match crate::turn_alloc::refresh_lifetime(requested, srv.max_lifetime) {
        // LIFETIME=0 is the teardown signal, handled before any clamp. Echoing
        // 600 here would make Chrome never release its port.
        crate::turn_alloc::RefreshOutcome::Delete => {
            if let Some(out) = refresh_success(m.txid, 0, Some(key), m.has_fingerprint) {
                reply.send(&out).await;
            }
            alloc.entry.cancel.cancel();
            teardown(srv, &tuple);
        }
        crate::turn_alloc::RefreshOutcome::Keep(n) => {
            alloc.expires.store(now() + n, Ordering::Relaxed);
            if let Some(out) = refresh_success(m.txid, n, Some(key), m.has_fingerprint) {
                reply.send(&out).await;
            }
        }
    }
}

async fn handle_create_permission(
    srv: &Arc<Server>,
    m: &stun::Message<'_>,
    alloc: &Arc<Allocation>,
    key: &[u8; 16],
    reply: &Reply,
) {
    let t = now();
    let fp = m.has_fingerprint;
    let fail = |code: u16, reason: &'static str| {
        error_response(code, reason, m.txid, method::CREATE_PERMISSION, Some(key), fp, &[])
    };

    // CreatePermission may carry MANY peer addresses; reading only the first
    // would silently drop permissions for clients that batch them.
    let raw = stun::all(m, attr::XOR_PEER_ADDRESS);
    if raw.is_empty() || raw.len() > srv.cfg.effective_max_permissions() {
        if let Some(out) = fail(if raw.is_empty() { 400 } else { 508 }, "Bad Request") {
            reply.send(&out).await;
        }
        return;
    }

    // Validate every peer BEFORE installing any: RFC 8656 §9.2 makes this
    // atomic, so a partially-rejected request must install nothing.
    let mut peers = Vec::with_capacity(raw.len());
    for v in raw {
        let Some(p) = stun::parse_xor_addr(&m.txid, v) else {
            if let Some(out) = fail(400, "Bad Request") {
                reply.send(&out).await;
            }
            return;
        };
        if family_of(p.ip()) != family_of(srv.relay_ip) {
            if let Some(out) = fail(443, "Peer Address Family Mismatch") {
                reply.send(&out).await;
            }
            return;
        }
        // IP-granularity only: RFC 8656 §9.2 ignores the port in a
        // CreatePermission, so a zero port here is legal, not malformed.
        if let Some(code) = srv.peer_ip_rejection(p.ip()) {
            // 403 for a policy refusal. libwebrtc prunes just that one
            // connection; 401 would be a terminal auth failure and silence
            // would burn its whole retransmission budget.
            if let Some(out) = fail(code, if code == 403 { "Forbidden" } else { "Bad Request" }) {
                reply.send(&out).await;
            }
            return;
        }
        peers.push(p);
    }

    // Install all or none. Capacity is checked first, inside the same lock, so
    // a request that cannot fit entirely leaves the table untouched rather than
    // installing a prefix and then answering 508.
    let fits = {
        let mut perms = alloc.perms.lock().unwrap();
        perms.sweep(t);
        let wanted: HashSet<IpAddr> = peers.iter().map(|p| p.ip()).collect();
        let new = wanted.iter().filter(|ip| !perms.allowed(**ip, t)).count();
        if perms.len() + new > srv.cfg.effective_max_permissions() {
            false
        } else {
            for ip in wanted {
                perms.install(ip, t);
            }
            true
        }
    };
    let out = if fits {
        bare_success(method::CREATE_PERMISSION, m.txid, Some(key), fp)
    } else {
        fail(508, "Insufficient Capacity")
    };
    if let Some(out) = out {
        reply.send(&out).await;
    }
}

async fn handle_channel_bind(
    srv: &Arc<Server>,
    m: &stun::Message<'_>,
    alloc: &Arc<Allocation>,
    key: &[u8; 16],
    reply: &Reply,
) {
    let t = now();
    let fp = m.has_fingerprint;
    let fail = |code: u16, reason: &'static str| {
        error_response(code, reason, m.txid, method::CHANNEL_BIND, Some(key), fp, &[])
    };

    let (Some(cn), Some(pv)) = (
        stun::first(m, attr::CHANNEL_NUMBER).filter(|v| v.len() == 4),
        stun::first(m, attr::XOR_PEER_ADDRESS),
    ) else {
        if let Some(out) = fail(400, "Bad Request") {
            reply.send(&out).await;
        }
        return;
    };
    let num = u16::from_be_bytes([cn[0], cn[1]]);
    let Some(peer) = stun::parse_xor_addr(&m.txid, pv) else {
        if let Some(out) = fail(400, "Bad Request") {
            reply.send(&out).await;
        }
        return;
    };
    if !crate::turn_alloc::valid_channel(num) {
        if let Some(out) = fail(400, "Bad Request") {
            reply.send(&out).await;
        }
        return;
    }
    if family_of(peer.ip()) != family_of(srv.relay_ip) {
        if let Some(out) = fail(443, "Peer Address Family Mismatch") {
            reply.send(&out).await;
        }
        return;
    }
    if let Some(code) = srv.peer_rejection(peer) {
        if let Some(out) = fail(code, if code == 403 { "Forbidden" } else { "Bad Request" }) {
            reply.send(&out).await;
        }
        return;
    }

    let bind = alloc.channels.lock().unwrap().bind(num, peer, t);
    match bind {
        crate::turn_alloc::BindResult::BadRequest => {
            if let Some(out) = fail(400, "Bad Request") {
                reply.send(&out).await;
            }
            return;
        }
        crate::turn_alloc::BindResult::Full => {
            if let Some(out) = fail(508, "Insufficient Capacity") {
                reply.send(&out).await;
            }
            return;
        }
        crate::turn_alloc::BindResult::Ok => {}
    }

    // A successful ChannelBind ALSO installs/refreshes the permission. Chrome
    // stops sending CreatePermission once a channel is bound and relies solely
    // on the 240 s ChannelBind refresh to keep both timers alive — treat the
    // two tables as independent and every call dies at exactly t=300 s, with
    // inbound traffic silently discarded and no error on either side.
    let installed = alloc.perms.lock().unwrap().install(peer.ip(), t);
    if !installed {
        if let Some(out) = fail(508, "Insufficient Capacity") {
            reply.send(&out).await;
        }
        return;
    }

    if let Some(out) = bare_success(method::CHANNEL_BIND, m.txid, Some(key), fp) {
        reply.send(&out).await;
    }
}

/// A Send indication: client → peer. Never answered, never authenticated
/// beyond the 5-tuple, and never refreshes a timer.
async fn handle_send(srv: &Arc<Server>, tuple: FiveTuple, m: &stun::Message<'_>) {
    let Some(alloc) = srv.allocations.get(&tuple).map(|a| a.clone()) else {
        return; // indications on an unknown 5-tuple are silently ignored
    };
    let (Some(pv), Some(data)) = (
        stun::first(m, attr::XOR_PEER_ADDRESS),
        stun::first(m, attr::DATA),
    ) else {
        return;
    };
    let Some(peer) = stun::parse_xor_addr(&m.txid, pv) else {
        return;
    };
    send_to_peer(srv, &alloc, peer, data).await;
}

/// A ChannelData frame: client → peer.
async fn handle_channel_data(srv: &Arc<Server>, tuple: FiveTuple, buf: &[u8]) {
    if buf.len() < 4 {
        return;
    }
    let num = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return; // declared length exceeds the datagram
    }
    let Some(alloc) = srv.allocations.get(&tuple).map(|a| a.clone()) else {
        return;
    };
    let t = now();
    let Some(peer) = alloc.channels.lock().unwrap().addr_of(num, t) else {
        return;
    };
    send_to_peer(srv, &alloc, peer, &buf[4..4 + len]).await;
}

/// Shared outbound path for Send indications and ChannelData.
async fn send_to_peer(srv: &Arc<Server>, alloc: &Arc<Allocation>, peer: SocketAddr, data: &[u8]) {
    let t = now();
    if !alloc.alive(t) {
        return;
    }
    let permitted = alloc.perms.lock().unwrap().allowed(peer.ip(), t);
    if !permitted || !srv.peer_send_allowed(peer) {
        // Counted rather than merely dropped, so a client hammering the server
        // with denied traffic is visible instead of looking idle.
        alloc.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    match alloc.relay.send_to(data, peer).await {
        Ok(n) => {
            alloc.entry.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        Err(e) => tracing::debug!("turn: relay send to {peer} failed: {e}"),
    }
}

/// Largest stream frame we will buffer: a maximal ChannelData plus its padding.
/// STUN messages are capped far lower by [`stun::MAX_MESSAGE`].
const MAX_FRAME: usize = 4 + 65535 + 3;

/// Cancel every allocation this server owns (listener shutdown).
fn cancel_all(srv: &Arc<Server>) {
    for a in srv.allocations.iter() {
        a.value().entry.cancel.cancel();
    }
}

/// Expire allocations whose time-to-expiry has passed.
///
/// This is the *only* expiry mechanism for a TURN allocation. `idle_timeout_secs`
/// is deliberately not applied: an allocation is legitimately silent for long
/// stretches (relay is last-resort in ICE, so a call that starts on host or
/// srflx has an idle allocation the whole time), and the client's keepalives —
/// Refresh every ~540 s, ChannelBind every 240 s — move no bytes, so a
/// byte-based idle timeout would tear down perfectly healthy allocations.
pub async fn reap(srv: Arc<Server>, token: tokio_util::sync::CancellationToken) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = tick.tick() => {
                let t = now();
                for a in srv.allocations.iter() {
                    if !a.value().alive(t) {
                        // Only cancel; the relay task owns teardown.
                        a.value().entry.cancel.cancel();
                    } else {
                        a.value().perms.lock().unwrap().sweep(t);
                        a.value().channels.lock().unwrap().sweep(t);
                    }
                }
            }
        }
    }
}

/// The UDP listener.
pub async fn serve_udp(
    srv: Arc<Server>,
    sock: Arc<UdpSocket>,
    token: tokio_util::sync::CancellationToken,
) {
    let server_addr = match sock.local_addr() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("turn: udp listener has no local address: {e}");
            return;
        }
    };
    // One datagram never exceeds a maximal STUN message or ChannelData frame.
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            r = sock.recv_from(&mut buf) => {
                let (n, peer) = match r {
                    Ok(v) => v,
                    Err(e) => { tracing::debug!("turn: udp recv failed: {e}"); continue; }
                };
                if srv.manager.peer_blocked(&srv.runtime, &peer) {
                    continue;
                }
                let tuple = FiveTuple {
                    client: peer,
                    server: server_addr,
                    transport: Transport::Udp,
                };
                let reply = Reply::Udp { sock: sock.clone(), to: peer };
                handle_message(&srv, tuple, &buf[..n], &reply).await;
            }
        }
    }
    cancel_all(&srv);
}

/// The TCP / TLS listener.
///
/// Deliberately not `Manager::accept_loop`: its per-connection semaphore would
/// double-count against the allocation cap. That means the three controls it
/// provides have to be reimplemented here — blocklist at accept, a connection
/// cap, and a bounded TLS handshake — plus one it does not have: a
/// pre-allocation idle timeout, so unauthenticated connections cannot be parked.
pub async fn serve_stream(
    srv: Arc<Server>,
    listener: tokio::net::TcpListener,
    token: tokio_util::sync::CancellationToken,
    tls: Option<TlsAcceptor>,
) {
    let server_addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("turn: stream listener has no local address: {e}");
            return;
        }
    };
    let transport = if tls.is_some() {
        Transport::Tls
    } else {
        Transport::Tcp
    };
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("turn: accept error: {e}"); continue; }
                };
                if srv.manager.peer_blocked(&srv.runtime, &peer) {
                    continue;
                }
                let Ok(permit) = srv.conn_sem.clone().try_acquire_owned() else {
                    tracing::debug!("turn: connection cap reached; refused {peer}");
                    continue;
                };
                let s = srv.clone();
                let t = token.clone();
                let acceptor = tls.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match acceptor {
                        None => {
                            serve_conn(s, stream, peer, server_addr, transport, t).await;
                        }
                        Some(acc) => {
                            // Bound the handshake: it is CPU work, so slowloris
                            // on turns: costs more than on plain TCP.
                            match tokio::time::timeout(
                                crate::relay::HANDSHAKE_TIMEOUT,
                                acc.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    serve_conn(s, tls_stream, peer, server_addr, transport, t).await;
                                }
                                Ok(Err(e)) => tracing::debug!("turn: TLS handshake failed: {e}"),
                                Err(_) => tracing::debug!("turn: TLS handshake timed out"),
                            }
                        }
                    }
                });
            }
        }
    }
    cancel_all(&srv);
}

/// One stream connection: frame, dispatch, and tear the allocation down on
/// FIN/RST so a reconnect from the same ephemeral port does not hit 437.
async fn serve_conn<S>(
    srv: Arc<Server>,
    stream: S,
    peer: SocketAddr,
    server_addr: SocketAddr,
    transport: Transport,
    token: tokio_util::sync::CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let tuple = FiveTuple {
        client: peer,
        server: server_addr,
        transport,
    };
    let (mut rd, wr) = tokio::io::split(stream);
    let reply = Reply::Stream(Arc::new(StreamWriter::new(Box::new(wr))));

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 4096];
    loop {
        // Dispatch every complete frame already buffered.
        loop {
            if buf.len() < 4 {
                break;
            }
            let Some(total) = frame_len(&buf) else {
                // A byte stream has no resynchronisation point, so an
                // unframeable byte means the connection is unusable.
                tracing::debug!("turn: unframeable byte from {peer}; closing");
                teardown(&srv, &tuple);
                return;
            };
            let cap = if buf[0] < 4 {
                stun::MAX_MESSAGE
            } else {
                MAX_FRAME
            };
            if total > cap {
                tracing::debug!("turn: oversized frame ({total}) from {peer}; closing");
                teardown(&srv, &tuple);
                return;
            }
            if buf.len() < total {
                break;
            }
            let frame: Vec<u8> = buf.drain(..total).collect();
            handle_message(&srv, tuple, &frame, &reply).await;
        }

        // Until this connection owns an allocation, cap how long it may sit
        // idle — accept_loop has no such control, so without it an attacker can
        // park connections that never authenticate.
        let idle = if srv.allocations.contains_key(&tuple) {
            None
        } else {
            Some(PRE_ALLOCATION_IDLE)
        };

        let read = async {
            match idle {
                None => rd.read(&mut chunk).await.map(Some),
                Some(d) => match tokio::time::timeout(d, rd.read(&mut chunk)).await {
                    Ok(r) => r.map(Some),
                    Err(_) => Ok(None),
                },
            }
        };

        tokio::select! {
            _ = token.cancelled() => break,
            r = read => match r {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => {
                    if buf.len() + n > MAX_FRAME * 2 {
                        tracing::debug!("turn: {peer} buffered past the frame cap; closing");
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) => {
                    tracing::debug!("turn: read from {peer} ended: {e}");
                    break;
                }
            }
        }
    }
    // FIN/RST ends the allocation: the 5-tuple must be free before the client
    // reconnects from the same ephemeral port.
    if let Some(a) = srv.allocations.get(&tuple).map(|a| a.clone()) {
        a.entry.cancel.cancel();
    }
    teardown(&srv, &tuple);
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
