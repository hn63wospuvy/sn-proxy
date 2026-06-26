//! SOCKS5 server (RFC 1928) with optional username/password auth (RFC 1929).
//!
//! Only the `CONNECT` command is supported, which is what proxy clients
//! (browsers, curl, etc.) use.

use crate::manager::{ConnEntry, Manager, ProxyRuntime};
use crate::relay;
use crate::udp_socks::{ParsedHost, build_udp_reply_header, parse_udp_request};
use anyhow::{Result, bail};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_REJECT: u8 = 0xFF;

/// One per-destination outbound socket plus its idle bookkeeping. `cancel`
/// fires when the per-destination idle reaper retires this socket, ending its
/// reply task.
struct DestEntry {
    sock: Arc<UdpSocket>,
    last_active: StdMutex<Instant>,
    cancel: CancellationToken,
}

/// Resolve a `ParsedHost` to a canonical `SocketAddr`, doing NO blocking I/O.
/// Returns `None` for a domain (caller handles the cache/off-loop path).
fn resolve_literal(host: &ParsedHost, port: u16) -> Option<SocketAddr> {
    match host {
        ParsedHost::V4(a) => Some(SocketAddr::new(
            Manager::canonicalize_ip(IpAddr::V4(Ipv4Addr::from(*a))),
            port,
        )),
        ParsedHost::V6(a) => Some(SocketAddr::new(
            Manager::canonicalize_ip(IpAddr::V6(Ipv6Addr::from(*a))),
            port,
        )),
        ParsedHost::Domain(_) => None,
    }
}

/// Handle a single accepted SOCKS5 client connection end to end.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    // Bound the whole pre-relay handshake so a client cannot stall mid-auth /
    // mid-request and pin the task + fd indefinitely (slow-loris).
    let req = tokio::time::timeout(relay::HANDSHAKE_TIMEOUT, async {
        negotiate_auth(&mut stream, &runtime).await?;
        read_request(&mut stream).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("socks5 handshake timed out"))??;
    match req.cmd {
        CMD_CONNECT => {
            let dst = req.host_port();
            let (connect_timeout, keepalive, idle) = {
                let cfg = runtime.config.lock().unwrap();
                (cfg.connect_timeout_secs, cfg.keepalive_secs, cfg.idle_timeout_secs)
            };
            let target = match relay::connect(&dst, connect_timeout, keepalive).await {
                Ok(t) => t,
                Err(e) => {
                    let _ = reply(&mut stream, 0x05).await; // connection refused
                    bail!("connect to {dst} failed: {e}");
                }
            };
            // Success: BND.ADDR/BND.PORT reported as 0.0.0.0:0.
            stream
                .write_all(&[VER, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
                let idle_fut = relay::idle_watchdog(
                    entry.clone(),
                    idle.filter(|s| *s > 0).map(Duration::from_secs),
                );
                let mut client = relay::Counting::new(stream, entry);
                let mut target = target;
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client, &mut target) => {}
                    _ = token.cancelled() => {}
                    _ = idle_fut => {}
                }
            })
            .await;
            Ok(())
        }
        CMD_UDP_ASSOCIATE => udp_associate(manager, runtime, stream, peer, token).await,
        _ => {
            let _ = reply(&mut stream, 0x07).await; // command not supported (incl. BIND 0x02)
            bail!("command not supported");
        }
    }
}

/// Perform the SOCKS5 method-selection handshake and, if the proxy requires
/// it, the RFC 1929 username/password exchange.
async fn negotiate_auth(stream: &mut TcpStream, runtime: &ProxyRuntime) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        bail!("not a socks5 client");
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;

    let auth = runtime.config.lock().unwrap().auth.clone();
    match auth {
        Some(auth) => {
            if !methods.contains(&METHOD_USERPASS) {
                stream.write_all(&[VER, METHOD_REJECT]).await?;
                bail!("client does not support username/password auth");
            }
            stream.write_all(&[VER, METHOD_USERPASS]).await?;

            // RFC 1929: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
            let mut h = [0u8; 2];
            stream.read_exact(&mut h).await?;
            if h[0] != 0x01 {
                bail!("unsupported auth subnegotiation version");
            }
            let mut uname = vec![0u8; h[1] as usize];
            stream.read_exact(&mut uname).await?;
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut passwd = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut passwd).await?;

            let ok = auth.username.as_bytes() == uname.as_slice()
                && auth.password.as_bytes() == passwd.as_slice();
            if ok {
                stream.write_all(&[0x01, 0x00]).await?;
                Ok(())
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                bail!("authentication failed");
            }
        }
        None => {
            if !methods.contains(&METHOD_NO_AUTH) {
                stream.write_all(&[VER, METHOD_REJECT]).await?;
                bail!("client insists on auth but proxy has none configured");
            }
            stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
            Ok(())
        }
    }
}

/// A parsed SOCKS5 request line (after method negotiation).
pub(crate) struct Socks5Request {
    pub cmd: u8,
    /// Address type of the request (unused until the UDP path consumes it).
    #[allow(dead_code)]
    pub atyp: u8,
    /// Host: a literal IPv4 (`1.2.3.4`), a bracketed IPv6 (`[::1]`), or a domain.
    pub host: String,
    pub port: u16,
}

impl Socks5Request {
    /// The destination as `host:port` (v6 host already carries brackets).
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Read the SOCKS5 request line. Does NOT dispatch on `cmd` — `serve` decides.
/// Still replies `0x08` (address type not supported) for an unknown ATYP.
async fn read_request(stream: &mut TcpStream) -> Result<Socks5Request> {
    let mut req = [0u8; 4]; // VER | CMD | RSV | ATYP
    stream.read_exact(&mut req).await?;
    if req[0] != VER {
        bail!("bad request version");
    }
    let cmd = req[1];
    let atyp = req[3];

    let host = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            format!("[{}]", Ipv6Addr::from(a))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            stream.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            let _ = reply(stream, 0x08).await; // address type not supported
            bail!("unsupported address type");
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    Ok(Socks5Request { cmd, atyp, host, port })
}

/// Send a SOCKS5 reply carrying only a status code.
async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream
        .write_all(&[VER, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Handle a SOCKS5 UDP ASSOCIATE (CMD=0x03). Lazily binds a client-facing
/// relay UDP socket, replies with BND.ADDR/BND.PORT, and runs the relay inside
/// `relay::tracked` with a 4-arm `select!` bound to the control connection.
async fn udp_associate(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    // 0. Feature gate.
    let (enabled, bind_cfg, advertise, max_dg, idle, allow_private, max_dests) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.udp_associate_enabled,
            cfg.udp_bind_addr.clone(),
            cfg.udp_advertise_ip.clone(),
            cfg.udp_max_datagram,
            cfg.idle_timeout_secs,
            cfg.udp_allow_private,
            cfg.udp_max_dests,
        )
    };
    if !enabled {
        let _ = reply(&mut stream, 0x07).await; // command not supported
        bail!("udp associate disabled");
    }
    // 1. Authorization gate: the UDP socket carries no credentials, so the
    //    authenticated control connection is the sole authorization.
    if manager.is_blocked(&peer) {
        let _ = reply(&mut stream, 0x02).await; // connection not allowed
        bail!("control peer blocked");
    }

    // 2. Bind the client-facing relay socket on the bind interface (default =
    //    the listener IP). Dual-stack caveat (S2): unmap a v4-mapped local IP.
    let listener_ip = match stream.local_addr() {
        Ok(a) => Manager::canonicalize_ip(a.ip()),
        Err(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    };
    let bind_ip: IpAddr = match bind_cfg.as_deref() {
        Some(s) if !s.is_empty() => match s.parse() {
            Ok(ip) => ip,
            Err(_) => listener_ip,
        },
        _ => listener_ip,
    };
    let relay_sock = match UdpSocket::bind((bind_ip, 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let _ = reply(&mut stream, 0x01).await; // general failure
            bail!("udp relay bind failed: {e}");
        }
    };
    let bnd_port = relay_sock.local_addr()?.port();

    // 3. Compute BND.ADDR: advertise override > concrete bind IP > wildcard
    //    fallback (emit 0.0.0.0/:: + rely on client substitution; warn).
    let bnd_ip: IpAddr = if let Some(a) = advertise.as_deref().filter(|s| !s.is_empty()) {
        a.parse().unwrap_or(bind_ip)
    } else if !bind_ip.is_unspecified() {
        bind_ip
    } else {
        tracing::warn!(
            "udp associate: wildcard bind with no udp_advertise_ip — BND.ADDR is \
             ambiguous behind NAT; set udp_advertise_ip"
        );
        bind_ip
    };
    let mut rep = vec![VER, 0x00, 0x00];
    match bnd_ip {
        IpAddr::V4(v4) => {
            rep.push(0x01);
            rep.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            rep.push(0x04);
            rep.extend_from_slice(&v6.octets());
        }
    }
    rep.extend_from_slice(&bnd_port.to_be_bytes());
    stream.write_all(&rep).await?;

    let max_datagram = max_dg.filter(|n| *n > 0).unwrap_or(64 * 1024);
    let idle_dur = idle
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60)); // UDP-specific default 60 s

    // 4. Register + run, bound to the control connection (B1: full IP:port).
    //    Clone the Arcs the relay loop needs so the closure owns them while
    //    `tracked` borrows `manager`/`runtime`.
    let loop_manager = manager.clone();
    let loop_runtime = runtime.clone();
    relay::tracked(
        &manager.storage,
        &runtime,
        peer.to_string(),
        "udp-associate".into(),
        |entry| async move {
            let idle_fut = relay::idle_watchdog(entry.clone(), Some(idle_dur));
            // The recv-loop body is implemented in Task 7; for this task it is a
            // placeholder that simply parks until torn down.
            let recv_loop = udp_relay_loop(
                loop_manager,
                loop_runtime,
                relay_sock.clone(),
                peer,
                entry.clone(),
                max_datagram,
                allow_private,
                max_dests,
                idle,
            );
            // Control-stream EOF read: one non-looped arm over a NON-zero buffer.
            let mut ctrl_buf = [0u8; 1];
            tokio::select! {
                _ = recv_loop => {}
                _ = stream.read(&mut ctrl_buf) => {} // Ok(0)=EOF, Err, or stray byte
                _ = token.cancelled() => {}
                _ = idle_fut => {}
            }
        },
    )
    .await;
    Ok(())
}

/// Per-datagram router for one UDP association. Owns the per-destination
/// outbound-socket map and the DNS cache, pins the client on the first accepted
/// datagram, canonicalizes the destination once, filters it, and forwards via
/// an atomic-claimed per-dest socket.
#[allow(clippy::too_many_arguments)]
async fn udp_relay_loop(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    relay_sock: Arc<UdpSocket>,
    peer: SocketAddr,
    entry: Arc<ConnEntry>,
    max_datagram: usize,
    allow_private: bool,
    max_dests: Option<u32>,
    idle_secs: Option<u64>,
) {
    // recv buffer holds DATA + worst-case domain header (7 + 255 = 262).
    let mut buf = vec![0u8; max_datagram + 262];
    let dests: Arc<DashMap<SocketAddr, Arc<DestEntry>>> = Arc::new(DashMap::new());
    // name -> (canonical SocketAddr, inserted_at) ; TTL-bounded cache.
    let dns_cache: Arc<DashMap<String, (SocketAddr, Instant)>> = Arc::new(DashMap::new());
    const DNS_TTL: Duration = Duration::from_secs(30);
    let mut pinned: Option<SocketAddr> = None;

    // Per-destination idle reaper: retire outbound sockets + reply tasks that
    // have seen no traffic for the idle bound (the same default the plain UDP
    // forwarder uses), so one association cannot pin sockets/tasks indefinitely.
    let (dest_idle, reaper_interval) = crate::udp::idle_bounds(idle_secs);
    let mut reaper = tokio::time::interval(reaper_interval);
    reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let (n, from) = tokio::select! {
            _ = reaper.tick() => {
                let now = Instant::now();
                for d in dests.iter() {
                    let idle_for = now.duration_since(*d.value().last_active.lock().unwrap());
                    if idle_for >= dest_idle {
                        // Cancel; the reply task is the sole owner of removal.
                        d.value().cancel.cancel();
                    }
                }
                continue;
            }
            r = relay_sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(_) => return, // unrecoverable relay-socket error
            },
        };
        // Pin: first datagram must come from the control peer IP; thereafter
        // accept only the exact pinned 2-tuple. All else dropped silently.
        match pinned {
            None => {
                if from.ip() != peer.ip() {
                    continue;
                }
                pinned = Some(from);
            }
            Some(p) => {
                if from != p {
                    continue;
                }
            }
        }
        let pkt = &buf[..n];
        let Some(hdr) = parse_udp_request(pkt) else {
            continue; // RSV/FRAG/length invalid → silent drop
        };
        let data = pkt[hdr.data_offset..].to_vec();

        match &hdr.host {
            ParsedHost::V4(_) | ParsedHost::V6(_) => {
                let Some(canon) = resolve_literal(&hdr.host, hdr.port) else {
                    continue;
                };
                forward_one(
                    &manager, &runtime, &relay_sock, &entry, &dests,
                    pinned.unwrap(), canon, data, allow_private, max_dests,
                )
                .await;
            }
            ParsedHost::Domain(name) => {
                let now = Instant::now();
                // Read the cache into a plain value, dropping the DashMap guard
                // before any await (never hold a Ref across `.await`).
                let cached = dns_cache
                    .get(name)
                    .filter(|c| now.duration_since(c.1) < DNS_TTL)
                    .map(|c| c.0);
                if let Some(canon) = cached {
                    forward_one(
                        &manager, &runtime, &relay_sock, &entry, &dests,
                        pinned.unwrap(), canon, data, allow_private, max_dests,
                    )
                    .await;
                    continue;
                }
                // Cache miss / TTL expiry: resolve OFF the recv loop (B3).
                // Honour the destination cap before spawning a resolver so a
                // flood of unique names cannot spawn unbounded lookup tasks.
                if let Some(cap) = max_dests
                    && dests.len() >= cap as usize
                {
                    continue;
                }
                let (m, rt, rs, en, ds, dc) = (
                    manager.clone(), runtime.clone(), relay_sock.clone(),
                    entry.clone(), dests.clone(), dns_cache.clone(),
                );
                let (name, port, client) = (name.clone(), hdr.port, pinned.unwrap());
                tokio::spawn(async move {
                    let lookup = format!("{name}:{port}");
                    let resolved = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::lookup_host(lookup),
                    )
                    .await;
                    let Ok(Ok(mut addrs)) = resolved else { return };
                    let Some(addr) = addrs.next() else { return };
                    let canon = SocketAddr::new(Manager::canonicalize_ip(addr.ip()), port);
                    dc.insert(name, (canon, Instant::now()));
                    forward_one(&m, &rt, &rs, &en, &ds, client, canon, data, allow_private, max_dests).await;
                });
            }
        }
    }
}

/// Filter, atomically claim a per-destination socket, and forward `DATA`.
#[allow(clippy::too_many_arguments)]
async fn forward_one(
    manager: &Arc<Manager>,
    runtime: &Arc<ProxyRuntime>,
    relay_sock: &Arc<UdpSocket>,
    entry: &Arc<ConnEntry>,
    dests: &Arc<DashMap<SocketAddr, Arc<DestEntry>>>,
    client: SocketAddr,
    canon: SocketAddr,
    data: Vec<u8>,
    allow_private: bool,
    max_dests: Option<u32>,
) {
    // Destination security filter on the CANONICAL address (B2/C1).
    if manager.dest_blocked(runtime, canon.ip(), canon.port()) {
        return;
    }
    if !allow_private && Manager::is_internal_dest(canon.ip()) {
        return;
    }
    // Atomic claim keyed by canonical dest: concurrent misses coalesce.
    // On bind/connect failure, silently drop (no panic).
    let dest = match dests.entry(canon) {
        dashmap::mapref::entry::Entry::Occupied(o) => o.get().clone(),
        dashmap::mapref::entry::Entry::Vacant(v) => {
            // Enforce the per-association destination cap: drop datagrams to new
            // destinations once the live socket count reaches the configured
            // limit (operator-facing `udp_max_dests`).
            if let Some(cap) = max_dests
                && dests.len() >= cap as usize
            {
                return;
            }
            let bind: SocketAddr = if canon.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let built = std::net::UdpSocket::bind(bind).and_then(|s| {
                s.set_nonblocking(true)?;
                s.connect(canon)?;
                Ok(s)
            });
            let Ok(std_sock) = built else { return };
            let Ok(sock) = UdpSocket::from_std(std_sock) else { return };
            let sock = Arc::new(sock);
            let de = Arc::new(DestEntry {
                sock: sock.clone(),
                last_active: StdMutex::new(Instant::now()),
                cancel: CancellationToken::new(),
            });
            spawn_reply_task(relay_sock.clone(), de.clone(), entry.clone(), client, dests.clone(), canon);
            v.insert(de.clone());
            de
        }
    };
    *dest.last_active.lock().unwrap() = Instant::now();
    if dest.sock.send(&data).await.is_ok() {
        entry.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
    }
}

/// Reply task: relay `dest`'s answers back to the pinned client. Loops `recv`
/// on the connected outbound socket, frames each reply with the responder's
/// literal IP, sends it to the pinned client, accounts payload-only, refreshes
/// the destination's `last_active`, and removes itself from `dests` on exit
/// (association teardown, per-destination idle reap, or a socket error).
fn spawn_reply_task(
    relay_sock: Arc<UdpSocket>,
    dest: Arc<DestEntry>,
    entry: Arc<ConnEntry>,
    client: SocketAddr,
    dests: Arc<DashMap<SocketAddr, Arc<DestEntry>>>,
    canon: SocketAddr,
) {
    tokio::spawn(async move {
        // Reply header is always a literal IP → worst case IPv6 (22 bytes).
        let mut buf = vec![0u8; 64 * 1024 + 22];
        loop {
            let n = tokio::select! {
                _ = entry.cancel.cancelled() => break, // association teardown
                _ = dest.cancel.cancelled() => break,  // per-dest idle reap
                r = dest.sock.recv(&mut buf) => match r {
                    Ok(n) => n,
                    Err(_) => break, // outbound socket error
                },
            };
            // `connect()`-ed socket only delivers from `canon`, so the responder
            // is the canonical dest; frame a literal-IP reply header.
            let mut out = build_udp_reply_header(canon);
            out.extend_from_slice(&buf[..n]);
            if relay_sock.send_to(&out, client).await.is_err() {
                break;
            }
            *dest.last_active.lock().unwrap() = Instant::now();
            entry.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
        }
        dests.remove(&canon);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_formats_v4_and_domain() {
        let r = Socks5Request { cmd: CMD_CONNECT, atyp: 0x01, host: "1.2.3.4".into(), port: 80 };
        assert_eq!(r.host_port(), "1.2.3.4:80");
        let d = Socks5Request { cmd: CMD_UDP_ASSOCIATE, atyp: 0x03, host: "example.com".into(), port: 443 };
        assert_eq!(d.host_port(), "example.com:443");
    }

    #[test]
    fn host_port_brackets_v6() {
        let r = Socks5Request { cmd: CMD_CONNECT, atyp: 0x04, host: "[::1]".into(), port: 9 };
        // host already carries brackets for v6 (matches read_request output).
        assert_eq!(r.host_port(), "[::1]:9");
    }
}
