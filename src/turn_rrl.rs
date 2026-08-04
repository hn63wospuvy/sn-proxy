//! Response rate limiting for the TURN listeners.
//!
//! A TURN server must answer an unauthenticated Allocate with a 401 challenge
//! carrying REALM and NONCE. That makes it a UDP reflection amplifier by
//! construction: a 28-byte request draws a ~90-byte response, from a spoofed
//! source, with no credential required.
//!
//! The limiter is a **fixed-size** array of token buckets indexed by a keyed
//! hash of the source IP. Fixed size is the whole point — the keys here are
//! attacker-controlled and spoofable, so the obvious `HashMap<IpAddr, _>`
//! (which is what [`crate::manager::AdminAuth`]'s login throttle uses, where
//! the keys are real TCP peers) would grow without bound under exactly the
//! flood it exists to stop. The mitigation would become the memory DoS.
//!
//! Collisions between distinct source IPs are accepted: two victims sharing a
//! bucket throttle each other slightly, which is far cheaper than unbounded
//! state. Authenticated traffic on an established allocation bypasses this
//! entirely — only unauthenticated responses are rate limited.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of buckets. A power of two so the index is a mask, not a modulo.
pub const DEFAULT_BUCKETS: usize = 4096;
/// Unauthenticated responses per second per bucket.
pub const DEFAULT_RATE: u32 = 10;

/// One bucket packed into a single `AtomicU64`: the low 32 bits are the token
/// count, the high 32 bits are the second the bucket was last refilled. Packing
/// them lets a bucket be updated with one compare-and-swap, so the datapath
/// takes no lock.
struct Bucket(AtomicU64);

impl Bucket {
    fn new(tokens: u32) -> Self {
        Self(AtomicU64::new(tokens as u64))
    }
}

fn pack(secs: u32, tokens: u32) -> u64 {
    ((secs as u64) << 32) | tokens as u64
}

fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

pub struct Rrl {
    buckets: Vec<Bucket>,
    mask: usize,
    rate: u32,
    /// Per-process key, so an attacker cannot compute which source addresses
    /// collide into one bucket and deliberately starve a chosen victim.
    key: u64,
}

impl Rrl {
    /// Build a limiter with `buckets` rounded up to a power of two (minimum 64)
    /// and `per_sec` tokens per bucket per second.
    pub fn new(buckets: usize, per_sec: u32) -> Self {
        let n = buckets.max(64).next_power_of_two();
        let mut key = [0u8; 8];
        // A failure here is not fatal: a fixed key still bounds memory, it only
        // loses the unpredictability of the bucket mapping.
        let _ = getrandom::fill(&mut key);
        Self {
            buckets: (0..n).map(|_| Bucket::new(per_sec)).collect(),
            mask: n - 1,
            rate: per_sec,
            key: u64::from_ne_bytes(key) | 1,
        }
    }

    /// Whether an unauthenticated response to `ip` may be sent now.
    ///
    /// `now_secs` is passed in rather than read from the clock so the datapath
    /// can reuse a timestamp it already has, and so this is testable.
    pub fn allow_at(&self, ip: IpAddr, now_secs: u32) -> bool {
        let b = &self.buckets[self.index(ip)];
        loop {
            let cur = b.0.load(Ordering::Relaxed);
            let (last, tokens) = unpack(cur);
            // Refill to full on any new second. A coarse refill is fine: the
            // goal is bounding amplification, not smooth shaping.
            let tokens = if now_secs != last { self.rate } else { tokens };
            if tokens == 0 {
                return false;
            }
            let next = pack(now_secs, tokens - 1);
            if b.0
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Number of buckets — fixed for the life of the limiter, whatever the
    /// traffic does.
    pub fn footprint(&self) -> usize {
        self.buckets.len()
    }

    fn index(&self, ip: IpAddr) -> usize {
        // FxHash-style mix over the address bytes. Not cryptographic; it only
        // has to spread addresses and stay unpredictable without the key.
        let mut h = self.key;
        let mix = |h: &mut u64, byte: u8| {
            *h = (*h ^ byte as u64).wrapping_mul(0x100_0000_01b3);
        };
        match ip {
            IpAddr::V4(v4) => v4.octets().iter().for_each(|b| mix(&mut h, *b)),
            // Hash the /64 rather than the full address: a v6 attacker usually
            // holds an entire prefix, so keying on all 128 bits would give them
            // a fresh bucket per packet.
            IpAddr::V6(v6) => v6.octets()[..8].iter().for_each(|b| mix(&mut h, *b)),
        }
        (h ^ (h >> 29)) as usize & self.mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn throttles_per_bucket_within_a_second() {
        let rrl = Rrl::new(64, 2);
        let ip = ip4(203, 0, 113, 1);
        assert!(rrl.allow_at(ip, 100));
        assert!(rrl.allow_at(ip, 100));
        assert!(!rrl.allow_at(ip, 100));
        // The next second refills.
        assert!(rrl.allow_at(ip, 101));
    }

    #[test]
    fn footprint_is_fixed_regardless_of_source_count() {
        // The keys are attacker-controlled and spoofable. A map keyed on them
        // would be the memory DoS it is supposed to prevent.
        let rrl = Rrl::new(64, 1);
        assert_eq!(rrl.footprint(), 64);
        for n in 0..50_000u32 {
            let o = n.to_be_bytes();
            let _ = rrl.allow_at(ip4(o[0], o[1], o[2], o[3]), 100);
        }
        assert_eq!(rrl.footprint(), 64);
    }

    #[test]
    fn buckets_round_up_to_a_power_of_two_with_a_floor() {
        assert_eq!(Rrl::new(4096, 1).footprint(), 4096);
        assert_eq!(Rrl::new(1000, 1).footprint(), 1024);
        assert_eq!(Rrl::new(1, 1).footprint(), 64);
        assert_eq!(Rrl::new(0, 1).footprint(), 64);
    }

    #[test]
    fn a_v6_prefix_does_not_get_a_fresh_bucket_per_packet() {
        // Keying on all 128 bits would let anyone holding a /64 walk the
        // address space and never hit a full bucket.
        let rrl = Rrl::new(64, 1);
        let base: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(rrl.allow_at(IpAddr::V6(base), 100));
        let sibling: std::net::Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        assert!(
            !rrl.allow_at(IpAddr::V6(sibling), 100),
            "addresses in one /64 must share a bucket"
        );
    }

    #[test]
    fn distinct_seconds_do_not_leak_tokens_backwards() {
        let rrl = Rrl::new(64, 1);
        let ip = ip4(198, 51, 100, 7);
        assert!(rrl.allow_at(ip, 200));
        assert!(!rrl.allow_at(ip, 200));
        assert!(rrl.allow_at(ip, 201));
        assert!(!rrl.allow_at(ip, 201));
    }
}
