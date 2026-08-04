//! Pure TURN allocation state: relay-port pool, permissions, channel bindings
//! and the lifetime arithmetic — no I/O, no sockets, no clock.
//!
//! Time is passed in as a Unix-seconds `u64` on every call that needs it, which
//! is what makes the whole module testable without a runtime. The consumers live
//! in `turn.rs`; the `dead_code` allow covers the window before those wire-ups.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Permission lifetime (RFC 8656 §9). Fixed by the RFC — deliberately not
/// configurable.
pub const PERMISSION_LIFETIME: u64 = 300;
/// Channel-binding lifetime (RFC 8656 §12). Also fixed.
pub const CHANNEL_LIFETIME: u64 = 600;
/// Default, and minimum grantable, allocation lifetime (RFC 8656 §7.2).
pub const DEFAULT_LIFETIME: u64 = 600;

/// Whether `n` is a channel number a client may use.
///
/// RFC 8656 narrowed this from RFC 5766's `0x4000..=0x7FFF`: `0x0000..=0x3FFF`
/// would collide with the STUN header's zero prefix, and `0x5000..=0xFFFF` is
/// reserved for DTLS-SRTP demultiplexing (RFC 7983). 4096 usable values.
pub fn valid_channel(n: u16) -> bool {
    (0x4000..=0x4FFF).contains(&n)
}

/// Lifetime granted for an **Allocate**.
///
/// `max(600, min(requested, server_max))`. The client's LIFETIME is advisory:
/// the RFC forbids granting less than 600 s, and Allocate — unlike Refresh —
/// gives no special meaning to a requested 0.
///
/// Total by construction: `server_max` is floored at [`DEFAULT_LIFETIME`] here
/// rather than trusted. The invariant is normally supplied by
/// `TurnConfig::effective_max_lifetime`, but relying on a guarantee made in
/// another module would turn a stray config value into a panic on the Allocate
/// path, and nothing on that path may panic.
pub fn granted_lifetime(requested: Option<u32>, server_max: u64) -> u64 {
    let ceiling = server_max.max(DEFAULT_LIFETIME);
    let asked = u64::from(requested.unwrap_or(DEFAULT_LIFETIME as u32));
    asked.clamp(DEFAULT_LIFETIME, ceiling)
}

/// What a **Refresh** asked for.
///
/// `LIFETIME=0` is not a short lifetime — it is how a client tears an allocation
/// down, and it MUST be handled before the clamp. libwebrtc's `TurnPort::Release`
/// sends it and branches on the *echoed* value: answer 600 and the client never
/// posts `MSG_ALLOCATION_RELEASED`, never closes its port, and reschedules
/// another refresh — while the server also holds the allocation for the full
/// lifetime. Every closed `PeerConnection` would then leak one allocation and
/// one relay port on both sides.
///
/// Returning an enum makes that mistake unrepresentable at this boundary instead
/// of relying on each caller to remember the special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// `LIFETIME=0`: delete the allocation and echo `LIFETIME=0`.
    Delete,
    /// Keep the allocation for this many seconds, and echo the same value.
    Keep(u64),
}

/// Resolve a Refresh request's LIFETIME. See [`RefreshOutcome`].
pub fn refresh_lifetime(requested: Option<u32>, server_max: u64) -> RefreshOutcome {
    match requested {
        Some(0) => RefreshOutcome::Delete,
        other => RefreshOutcome::Keep(granted_lifetime(other, server_max)),
    }
}

/// The pool of relay ports a TURN proxy may allocate from.
///
/// Two properties matter beyond "hands out a free port":
///
/// **Ports are never handed out twice.** A double `give` — the likeliest caller
/// bug here, via a drop guard plus an explicit release, or an error path that
/// releases and then unwinds — would bind two allocations to one relay socket.
/// Because TURN permissions are keyed on peer IP only, neither client could then
/// filter out the other's peers. So membership is tracked, and `give` is a no-op
/// for a port that is already free or was never taken.
///
/// **Reclaim is randomised, not LIFO.** A plain `pop`/`push` free list hands a
/// just-released port straight back out, which defeats the shuffle entirely: an
/// authenticated attacker could allocate, note the port, release, and know the
/// next client's relay port exactly. Since permissions are IP-only, anyone
/// sharing a permitted IP with that client could then inject media into the
/// session. Released ports are therefore swapped to a random position.
pub struct PortPool {
    min: u16,
    /// Ports currently available, in the order they will be handed out.
    free: Vec<u16>,
    /// `is_free[port - min]` — the membership index that makes `give`
    /// idempotent.
    is_free: Vec<bool>,
}

impl PortPool {
    /// Build a pool over the inclusive range `[min, max]`, shuffled with a
    /// CSPRNG.
    ///
    /// `min > max` yields an empty pool (every `take` returns `None`, so the
    /// caller answers 508) rather than panicking — a misconfigured range must
    /// not take a listener down.
    pub fn new(min: u16, max: u16) -> Self {
        if min > max {
            return Self {
                min,
                free: Vec::new(),
                is_free: Vec::new(),
            };
        }
        let mut free: Vec<u16> = (min..=max).collect();
        shuffle(&mut free);
        let is_free = vec![true; free.len()];
        Self { min, free, is_free }
    }

    /// Claim a port, or `None` when the pool is exhausted (caller answers 508).
    pub fn take(&mut self) -> Option<u16> {
        let port = self.free.pop()?;
        let i = self.index(port)?;
        self.is_free[i] = false;
        Some(port)
    }

    /// Return a port to the pool. A no-op for a port outside the range or one
    /// that is already free.
    pub fn give(&mut self, port: u16) {
        let Some(i) = self.index(port) else { return };
        if self.is_free[i] {
            return; // double release — must not create a duplicate
        }
        self.is_free[i] = true;
        self.free.push(port);
        // Swap the returned port to a random position so it is not the next one
        // out. Without this the construction-time shuffle protects only the
        // first pass through the range.
        let n = self.free.len();
        if n > 1 {
            let j = random_below(n);
            self.free.swap(n - 1, j);
        }
    }

    pub fn available(&self) -> usize {
        self.free.len()
    }

    pub fn capacity(&self) -> usize {
        self.is_free.len()
    }

    fn index(&self, port: u16) -> Option<usize> {
        let i = usize::from(port.checked_sub(self.min)?);
        (i < self.is_free.len()).then_some(i)
    }
}

/// Fisher-Yates over a CSPRNG.
///
/// A `getrandom` failure degrades to a clock-seeded SplitMix64 rather than
/// panicking: this runs on the Allocate path, and a panic there would be a
/// remote DoS. The degraded order is weaker but still non-sequential, which is
/// the property that actually defends the relay port.
fn shuffle(v: &mut [u16]) {
    for i in (1..v.len()).rev() {
        v.swap(i, random_below(i + 1));
    }
}

/// A uniform-ish index in `0..n`. Modulo bias is bounded by `n / 2^64`, which is
/// negligible for a port range.
fn random_below(n: usize) -> usize {
    let mut buf = [0u8; 8];
    let r = if getrandom::fill(&mut buf).is_ok() {
        u64::from_ne_bytes(buf)
    } else {
        fallback_random()
    };
    (r % n as u64) as usize
}

/// SplitMix64 seeded from the clock, used only when `getrandom` fails.
fn fallback_random() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let seed = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
        ^ crate::model::now_ms() as u64;
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Peer addresses this allocation may exchange traffic with.
///
/// Keyed on the **IP only** — RFC 8656 explicitly ignores the port, so a
/// permission for `1.2.3.4` covers every port on that host.
pub struct Permissions {
    map: HashMap<IpAddr, u64>,
    cap: usize,
}

impl Permissions {
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
        }
    }

    /// Install or refresh a permission. Returns `false` when a *new* IP would
    /// exceed the cap (the caller answers 508).
    ///
    /// Refreshing an existing permission never consumes a slot, or a client
    /// sitting at the cap could never refresh and would lose every permission at
    /// once mid-call. Expired entries are swept first for the same reason: they
    /// are already dead, and counting them would lock a client out of new peers
    /// on the strength of state that no longer grants anything.
    pub fn install(&mut self, ip: IpAddr, now: u64) -> bool {
        if let Some(exp) = self.map.get_mut(&ip) {
            *exp = now + PERMISSION_LIFETIME;
            return true;
        }
        self.sweep(now);
        if self.map.len() >= self.cap {
            return false;
        }
        self.map.insert(ip, now + PERMISSION_LIFETIME);
        true
    }

    /// Whether traffic to/from `ip` is currently permitted. An entry expires
    /// *at* its expiry instant, not after it.
    pub fn allowed(&self, ip: IpAddr, now: u64) -> bool {
        self.map.get(&ip).is_some_and(|exp| *exp > now)
    }

    pub fn sweep(&mut self, now: u64) {
        self.map.retain(|_, exp| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Outcome of a ChannelBind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindResult {
    Ok,
    /// A conflict, or a channel number outside `0x4000..=0x4FFF` — 400.
    BadRequest,
    /// At the per-allocation channel cap — 508.
    Full,
}

/// Channel-number ↔ peer-address bindings, in both directions.
pub struct Channels {
    fwd: HashMap<u16, (SocketAddr, u64)>,
    rev: HashMap<SocketAddr, u16>,
    cap: usize,
}

impl Channels {
    pub fn new(cap: usize) -> Self {
        Self {
            fwd: HashMap::new(),
            rev: HashMap::new(),
            cap,
        }
    }

    /// Bind (or refresh) `num` ↔ `addr`.
    ///
    /// Re-binding the identical pair is the normal keepalive path and returns
    /// `Ok`. A channel already bound to a *different* address, or an address
    /// already bound to a *different* channel, is `BadRequest`.
    ///
    /// Expired bindings are swept first, so a dead binding can neither
    /// manufacture a conflict nor hold a capacity slot against a live request.
    /// An expired channel may be rebound immediately: the five-minute
    /// quarantine in RFC 8656 §12 is normatively a *client* obligation, and
    /// enforcing it server-side would reject conformant-but-aggressive clients.
    pub fn bind(&mut self, num: u16, addr: SocketAddr, now: u64) -> BindResult {
        if !valid_channel(num) {
            return BindResult::BadRequest;
        }
        self.sweep(now);
        match (self.fwd.get(&num), self.rev.get(&addr)) {
            (Some((bound, _)), _) if *bound != addr => BindResult::BadRequest,
            (_, Some(bound)) if *bound != num => BindResult::BadRequest,
            (Some(_), _) => {
                // Same pair — refresh.
                self.fwd.insert(num, (addr, now + CHANNEL_LIFETIME));
                BindResult::Ok
            }
            _ => {
                if self.fwd.len() >= self.cap {
                    return BindResult::Full;
                }
                self.fwd.insert(num, (addr, now + CHANNEL_LIFETIME));
                self.rev.insert(addr, num);
                BindResult::Ok
            }
        }
    }

    pub fn addr_of(&self, num: u16, now: u64) -> Option<SocketAddr> {
        self.fwd
            .get(&num)
            .filter(|(_, exp)| *exp > now)
            .map(|(a, _)| *a)
    }

    pub fn num_of(&self, addr: SocketAddr, now: u64) -> Option<u16> {
        let num = *self.rev.get(&addr)?;
        self.fwd
            .get(&num)
            .filter(|(_, exp)| *exp > now)
            .map(|_| num)
    }

    /// Drop expired bindings from both indexes together — a stale reverse entry
    /// would make a legitimate rebind fail forever.
    pub fn sweep(&mut self, now: u64) {
        let rev = &mut self.rev;
        self.fwd.retain(|_, (addr, exp)| {
            if *exp > now {
                true
            } else {
                rev.remove(addr);
                false
            }
        });
    }

    pub fn len(&self) -> usize {
        self.fwd.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fwd.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }
    fn sa(n: u8, p: u16) -> SocketAddr {
        SocketAddr::new(ip(n), p)
    }

    #[test]
    fn channel_range_is_rfc8656_not_rfc5766() {
        // RFC 8656 narrowed the usable range; 0x5000-0x7FFF was legal under
        // 5766 and is now reserved for DTLS-SRTP demux.
        assert!(!valid_channel(0x3FFF));
        assert!(valid_channel(0x4000));
        assert!(valid_channel(0x4FFF));
        assert!(!valid_channel(0x5000));
        assert!(!valid_channel(0x7FFF));
    }

    #[test]
    fn lifetime_is_floored_at_600_and_capped_by_the_server() {
        assert_eq!(granted_lifetime(None, 3600), DEFAULT_LIFETIME);
        assert_eq!(granted_lifetime(Some(60), 3600), 600); // floored
        assert_eq!(granted_lifetime(Some(1800), 3600), 1800);
        assert_eq!(granted_lifetime(Some(99999), 3600), 3600); // capped
    }

    #[test]
    fn granted_lifetime_is_total_even_for_an_inverted_ceiling() {
        // The 600-floor invariant is supplied by TurnConfig in another module.
        // Trusting it would turn a stray config value into a panic on the
        // Allocate path, which must never panic.
        assert_eq!(granted_lifetime(Some(1800), 300), 600);
        assert_eq!(granted_lifetime(None, 0), 600);
        // The grant is bounded by what the client asked for, so a huge ceiling
        // does not inflate it past the request.
        assert_eq!(
            granted_lifetime(Some(u32::MAX), u64::MAX),
            u64::from(u32::MAX)
        );
    }

    #[test]
    fn refresh_zero_is_delete_not_a_clamped_lifetime() {
        // Answering 600 here makes Chrome never release its port: it branches
        // on the echoed value, so both sides leak an allocation per call.
        assert_eq!(refresh_lifetime(Some(0), 3600), RefreshOutcome::Delete);
        assert_eq!(refresh_lifetime(Some(60), 3600), RefreshOutcome::Keep(600));
        assert_eq!(refresh_lifetime(None, 3600), RefreshOutcome::Keep(600));
        assert_eq!(refresh_lifetime(Some(1800), 3600), RefreshOutcome::Keep(1800));
    }

    #[test]
    fn port_pool_hands_out_every_port_once_then_reports_empty() {
        let mut p = PortPool::new(50000, 50003);
        assert_eq!(p.capacity(), 4);
        let mut got = Vec::new();
        while let Some(port) = p.take() {
            got.push(port);
        }
        got.sort_unstable();
        assert_eq!(got, vec![50000, 50001, 50002, 50003]);
        assert_eq!(p.take(), None); // exhausted -> caller returns 508
        p.give(50002);
        assert_eq!(p.take(), Some(50002));
    }

    #[test]
    fn port_pool_order_is_not_sequential() {
        // A predictable relay port lets an off-path attacker locate a victim's
        // relay socket, and permissions are IP-only, so any host behind a
        // permitted IP could then inject media.
        let mut p = PortPool::new(50000, 50255);
        let first: Vec<u16> = (0..8).filter_map(|_| p.take()).collect();
        let sequential: Vec<u16> = (50000..50008).collect();
        assert_ne!(first, sequential);
    }

    #[test]
    fn port_pool_double_give_cannot_duplicate_a_port() {
        // A double release is the likeliest caller bug here, and the cost is
        // two allocations sharing one relay socket — which IP-only permissions
        // cannot filter apart.
        let mut p = PortPool::new(50000, 50003);
        let a = p.take().unwrap();
        p.give(a);
        p.give(a);
        p.give(a);
        assert_eq!(p.available(), 4);
        let mut drained = Vec::new();
        while let Some(port) = p.take() {
            drained.push(port);
        }
        assert_eq!(drained.len(), 4, "capacity must not grow");
        drained.sort_unstable();
        drained.dedup();
        assert_eq!(drained.len(), 4, "no port may be issued twice");
        // A port that was never taken, and one out of range, are both no-ops.
        let mut q = PortPool::new(50000, 50001);
        q.give(50000);
        q.give(49999);
        q.give(60000);
        assert_eq!(q.available(), 2);
    }

    #[test]
    fn port_pool_does_not_hand_a_freed_port_straight_back() {
        // LIFO reclaim would let an attacker allocate, note the port, release,
        // and know the next client's relay port exactly.
        let mut p = PortPool::new(50000, 50255);
        let mut immediate = 0;
        for _ in 0..40 {
            let a = p.take().unwrap();
            // Hold a few others so the freed port is not the only candidate.
            let held: Vec<u16> = (0..4).filter_map(|_| p.take()).collect();
            p.give(a);
            let next = p.take().unwrap();
            if next == a {
                immediate += 1;
            }
            p.give(next);
            for h in held {
                p.give(h);
            }
        }
        assert!(
            immediate < 30,
            "freed port came back immediately {immediate}/40 times — reclaim is effectively LIFO"
        );
    }

    #[test]
    fn port_pool_empty_range_does_not_panic() {
        let mut p = PortPool::new(50100, 50000);
        assert_eq!(p.capacity(), 0);
        assert_eq!(p.take(), None);
        p.give(50050); // no-op, must not panic
    }

    #[test]
    fn permissions_expire_at_300s_and_are_keyed_on_ip_only() {
        let mut perms = Permissions::new(8);
        assert!(perms.install(ip(1), 1000));
        // Port is explicitly ignored by the RFC: any port on a permitted IP.
        assert!(perms.allowed(ip(1), 1000));
        assert!(perms.allowed(ip(1), 1000 + PERMISSION_LIFETIME - 1));
        assert!(!perms.allowed(ip(1), 1000 + PERMISSION_LIFETIME + 1));
        assert!(!perms.allowed(ip(2), 1000));
    }

    #[test]
    fn permissions_cap_is_enforced_and_refresh_does_not_consume_a_slot() {
        let mut perms = Permissions::new(2);
        assert!(perms.install(ip(1), 1000));
        assert!(perms.install(ip(2), 1000));
        assert!(!perms.install(ip(3), 1000)); // caller returns 508
        // Refreshing an existing permission must still work at the cap.
        assert!(perms.install(ip(1), 1200));
        assert!(perms.allowed(ip(1), 1400));
    }

    #[test]
    fn expired_permissions_do_not_hold_capacity_slots() {
        // Otherwise a client at the cap is locked out of new peers mid-call by
        // state that no longer grants anything.
        let mut perms = Permissions::new(2);
        assert!(perms.install(ip(1), 1000));
        assert!(perms.install(ip(2), 1000));
        let later = 1000 + PERMISSION_LIFETIME + 1;
        assert!(!perms.allowed(ip(1), later));
        assert!(
            perms.install(ip(3), later),
            "a dead permission must not count against the cap"
        );
    }

    #[test]
    fn channels_bind_both_directions_and_expire_at_600s() {
        let mut ch = Channels::new(4);
        assert_eq!(ch.bind(0x4001, sa(1, 9000), 1000), BindResult::Ok);
        assert_eq!(ch.addr_of(0x4001, 1000), Some(sa(1, 9000)));
        assert_eq!(ch.num_of(sa(1, 9000), 1000), Some(0x4001));
        assert_eq!(ch.addr_of(0x4001, 1000 + CHANNEL_LIFETIME + 1), None);
        assert_eq!(ch.num_of(sa(1, 9000), 1000 + CHANNEL_LIFETIME + 1), None);
    }

    #[test]
    fn channel_conflicts_are_bad_request_but_rebinding_the_same_pair_is_ok() {
        let mut ch = Channels::new(4);
        assert_eq!(ch.bind(0x4001, sa(1, 9000), 1000), BindResult::Ok);
        // Same channel, different peer.
        assert_eq!(ch.bind(0x4001, sa(2, 9000), 1000), BindResult::BadRequest);
        // Same peer, different channel.
        assert_eq!(ch.bind(0x4002, sa(1, 9000), 1000), BindResult::BadRequest);
        // Refreshing the identical pair is the normal keepalive path.
        assert_eq!(ch.bind(0x4001, sa(1, 9000), 1300), BindResult::Ok);
        assert_eq!(ch.addr_of(0x4001, 1800), Some(sa(1, 9000)));
        // The refresh must not have duplicated the binding.
        assert_eq!(ch.len(), 1);
    }

    #[test]
    fn expired_channel_may_be_rebound_immediately() {
        // The 5-minute quarantine is normatively a CLIENT obligation. A
        // server-side quarantine would break conformant-but-aggressive clients.
        let mut ch = Channels::new(4);
        assert_eq!(ch.bind(0x4001, sa(1, 9000), 1000), BindResult::Ok);
        let later = 1000 + CHANNEL_LIFETIME + 1;
        ch.sweep(later);
        assert_eq!(ch.bind(0x4001, sa(2, 9000), later), BindResult::Ok);
        // The old reverse entry must be gone, or the old peer could never be
        // bound to a new channel.
        assert_eq!(ch.num_of(sa(1, 9000), later), None);
        assert_eq!(ch.bind(0x4002, sa(1, 9000), later), BindResult::Ok);
    }

    #[test]
    fn channel_cap_is_enforced() {
        let mut ch = Channels::new(1);
        assert_eq!(ch.bind(0x4001, sa(1, 9000), 1000), BindResult::Ok);
        assert_eq!(ch.bind(0x4002, sa(2, 9000), 1000), BindResult::Full);
    }

    #[test]
    fn out_of_range_channel_number_is_refused() {
        // turn.rs validates first so it can emit 400 with the right reason, but
        // a caller bug must not be able to create an unreachable binding.
        let mut ch = Channels::new(4);
        assert_eq!(ch.bind(0x3FFF, sa(1, 9000), 1000), BindResult::BadRequest);
        assert_eq!(ch.bind(0x5000, sa(1, 9000), 1000), BindResult::BadRequest);
        assert!(ch.is_empty());
    }
}
