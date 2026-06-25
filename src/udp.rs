//! Plain UDP forwarder: each datagram on the listen port is relayed to a
//! fixed `forward_to` destination, with per-source-address sessions reaped by
//! an idle timeout.

use crate::manager::{ConnEntry, Manager, ProxyRuntime};
use crate::relay;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// One client-source-address session: the monitored [`ConnEntry`], a
/// `connect()`-ed upstream socket, and the last-active timestamp the reaper
/// reads. `last_active` is Unix-ms, read/written `Relaxed` (a reaper
/// heuristic, not a synchronization point).
struct Session {
    entry: Arc<ConnEntry>,
    upstream: Arc<UdpSocket>,
    last_active: AtomicU64,
}

/// Compute the idle bound and reaper interval for a UDP listener.
///
/// UDP diverges from the TCP "0/None = disabled" rule: an unset or `0` idle
/// still reaps at 60 s, or sessions would leak. The reaper interval is capped
/// at 5 s so a small configured idle still reaps promptly while a large idle
/// does not make the reaper spin needlessly. The interval is always `<= idle`.
pub(crate) fn idle_bounds(idle_secs: Option<u64>) -> (Duration, Duration) {
    let idle = idle_secs.filter(|s| *s > 0).unwrap_or(60);
    let interval = idle.min(5);
    (Duration::from_secs(idle), Duration::from_secs(interval))
}

/// Run the UDP forwarder until `token` is cancelled.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    socket: Arc<UdpSocket>,
    token: CancellationToken,
) {
    // Read the fixed destination + idle config once.
    let (dst_str, idle_secs) = {
        let cfg = runtime.config.lock().unwrap();
        (cfg.forward_to.clone(), cfg.idle_timeout_secs)
    };
    let dst_str = match dst_str {
        Some(d) if !d.is_empty() => d,
        _ => {
            tracing::warn!("udp proxy has no forward destination; not starting");
            runtime.running.store(false, Ordering::SeqCst);
            return;
        }
    };

    // Resolve the destination ONCE at startup (keeps DNS off the recv loop).
    let dst_addr: SocketAddr = match tokio::net::lookup_host(&dst_str).await {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                tracing::warn!("udp forward destination {dst_str} resolved to no addresses");
                runtime.running.store(false, Ordering::SeqCst);
                return;
            }
        },
        Err(e) => {
            tracing::warn!("cannot resolve udp forward destination {dst_str}: {e}");
            runtime.running.store(false, Ordering::SeqCst);
            return;
        }
    };

    let (idle, reaper_interval) = idle_bounds(idle_secs);
    let sessions: Arc<DashMap<SocketAddr, Arc<Session>>> = Arc::new(DashMap::new());
    let mut buf = vec![0u8; 64 * 1024];
    let mut reaper = tokio::time::interval(reaper_interval);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                // Listener shutdown: cancel every session. The reader task is
                // the single owner of sessions.remove + udp_session_end.
                for s in sessions.iter() {
                    s.value().entry.cancel.cancel();
                }
                break;
            }
            _ = reaper.tick() => {
                let now = crate::model::now_ms() as u64;
                let idle_ms = idle.as_millis() as u64;
                for s in sessions.iter() {
                    let last = s.value().last_active.load(Ordering::Relaxed);
                    if now.saturating_sub(last) >= idle_ms {
                        // Only cancel; the reader task does the teardown.
                        s.value().entry.cancel.cancel();
                    }
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => { tracing::debug!("udp recv_from error: {e}"); continue; }
                };
                if manager.peer_blocked(&runtime, &peer) {
                    tracing::debug!("udp dropped datagram from blocked peer {peer}");
                    continue;
                }
                let session = match get_or_create_session(
                    &manager, &runtime, &socket, &sessions, peer, dst_addr,
                ) {
                    Some(s) => s,
                    None => continue, // bind/connect failed; datagram dropped
                };
                // Forward this datagram (including the very first one).
                match session.upstream.send(&buf[..n]).await {
                    Ok(sent) => {
                        session.entry.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
                        session.last_active.store(crate::model::now_ms() as u64, Ordering::Relaxed);
                    }
                    Err(e) => tracing::debug!("udp upstream send to {dst_addr} failed: {e}"),
                }
            }
        }
    }
    runtime.running.store(false, Ordering::SeqCst);
}

/// Return the session for `peer`, creating one synchronously on the recv loop
/// if absent. The `sessions` slot is claimed via the `DashMap` entry API so a
/// burst from a new peer coalesces onto one session. Binding + `connect()` to
/// an already-resolved `SocketAddr` does no network round-trip, so this is
/// cheap enough to run on-loop. Returns `None` if the upstream socket could
/// not be created (datagram is dropped, no session inserted).
fn get_or_create_session(
    manager: &Arc<Manager>,
    runtime: &Arc<ProxyRuntime>,
    socket: &Arc<UdpSocket>,
    sessions: &Arc<DashMap<SocketAddr, Arc<Session>>>,
    peer: SocketAddr,
    dst_addr: SocketAddr,
) -> Option<Arc<Session>> {
    match sessions.entry(peer) {
        Entry::Occupied(e) => Some(e.get().clone()),
        Entry::Vacant(slot) => {
            // Bind an ephemeral upstream socket matching the destination family.
            let bind_addr = if dst_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let upstream = match std::net::UdpSocket::bind(bind_addr)
                .and_then(|s| { s.set_nonblocking(true)?; s.connect(dst_addr)?; Ok(s) })
                .and_then(UdpSocket::from_std)
            {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::debug!("udp upstream bind/connect for {peer} failed: {e}");
                    return None; // leave the slot vacant, drop the datagram
                }
            };

            let entry = relay::udp_session_start(runtime, peer.to_string(), dst_addr.to_string());
            let session = Arc::new(Session {
                entry: entry.clone(),
                upstream: upstream.clone(),
                last_active: AtomicU64::new(crate::model::now_ms() as u64),
            });
            slot.insert(session.clone());

            // Spawn the upstream reader task — sole owner of teardown.
            let manager = manager.clone();
            let runtime = runtime.clone();
            let sessions = sessions.clone();
            let listen = socket.clone();
            tokio::spawn(async move {
                reader_task(manager, runtime, sessions, listen, peer, entry, upstream).await;
            });
            Some(session)
        }
    }
}

/// Per-session upstream reader. The SINGLE place that removes the session and
/// writes history: every exit cause (idle cancel, admin kill/block, listener
/// shutdown, upstream error) converges by firing `entry.cancel.cancel()`,
/// which ends this loop, which runs teardown exactly once.
async fn reader_task(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    sessions: Arc<DashMap<SocketAddr, Arc<Session>>>,
    listen: Arc<UdpSocket>,
    peer: SocketAddr,
    entry: Arc<ConnEntry>,
    upstream: Arc<UdpSocket>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            _ = entry.cancel.cancelled() => break,
            r = upstream.recv(&mut buf) => match r {
                Ok(n) => {
                    if let Err(e) = listen.send_to(&buf[..n], peer).await {
                        tracing::debug!("udp reply to {peer} failed: {e}");
                        break;
                    }
                    entry.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(s) = sessions.get(&peer) {
                        s.value().last_active.store(
                            crate::model::now_ms() as u64,
                            Ordering::Relaxed,
                        );
                    }
                }
                Err(e) => { tracing::debug!("udp upstream recv for {peer} ended: {e}"); break; }
            }
        }
    }
    // Single-owner teardown.
    sessions.remove(&peer);
    relay::udp_session_end(&manager.storage, &runtime, &entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_default_is_60s_when_unset_or_zero() {
        assert_eq!(idle_bounds(None).0, Duration::from_secs(60));
        assert_eq!(idle_bounds(Some(0)).0, Duration::from_secs(60));
    }

    #[test]
    fn reaper_interval_is_capped_at_5s() {
        // default 60 s idle -> 5 s interval
        assert_eq!(idle_bounds(None).1, Duration::from_secs(5));
        // large idle -> still 5 s interval
        assert_eq!(idle_bounds(Some(120)).1, Duration::from_secs(5));
        // small idle -> interval == idle, never larger
        assert_eq!(idle_bounds(Some(1)), (Duration::from_secs(1), Duration::from_secs(1)));
        assert_eq!(idle_bounds(Some(3)).1, Duration::from_secs(3));
    }
}
