# Security Audit — sn-proxy

**Date:** 2026-06-26
**Scope:** entire `src/*.rs` (~6.3k LoC) + `static/index.html` (~1.5k LoC) + config/deps.
**Method:** multi-agent review across 11 security dimensions covering every source
file; each candidate finding was adversarially verified against the cited code to
filter false positives. 42 candidates → 34 confirmed, 8 refuted.

**Threat model.** The web admin may be *open by default* (no login) unless an admin
account is configured; when configured, auth is a session cookie with an optional
per-admin CIDR. Listeners accept bytes from untrusted network clients. Proxies
forward arbitrary client traffic *by design*. The project follows a
**permissive-with-warnings** philosophy: support insecure options but warn, rather
than forbidding them.

---

## Status overview

| Severity | Confirmed | Fixed | Outstanding |
|----------|-----------|-------|-------------|
| High     | 5         | 4     | 1 (H1)      |
| Medium   | 8         | 5     | 2 (M2, M4) + 1 by-design (M6) |
| Low      | 15        | 0     | 15          |
| Info     | 1         | 0     | 1           |

Online brute-force throttling (`M8`) was added as extra hardening and partially
mitigates the timing-oracle / credential-probing low findings (L1, L3, L14).

---

## Fixed in this branch

| ID | Title | Where |
|----|-------|-------|
| H2 | Stored XSS via proxy name in `onclick` handlers | `esc()` now escapes `'` `` ` ``; server-side name validation in `ProxySpec::validate` |
| H3 | Stored XSS via blocklist address | closed by the same `esc()` fix |
| H4 | No handshake/read timeout before relay (slow-loris) | `relay::HANDSHAKE_TIMEOUT` (30s) wraps the SOCKS5/HTTP/WS/Shadowsocks handshakes and the HTTPS-listener TLS accept |
| H5 | `udp_max_dests` never enforced | enforced in `forward_one`; DNS-resolver spawns also gated by the cap |
| M1 | Session cookie missing `Secure` over cleartext | opt-in `admin_https` adds `Secure`; startup warning when auth runs over plain HTTP |
| M3 | Shadowsocks salt-reuse / replay | bounded per-proxy salt cache (`SaltCache`, 16 384 entries) rejects reused salts |
| M5 | No connection cap | per-proxy `max_connections` (default **8888**, `0`=unlimited) enforced via a semaphore in the accept loop |
| M6 | Idle timeout disabled by default | *intentional* — see Outstanding; mitigated by M5 + H4 |
| M7 | UDP per-destination sockets/buffers never idle-reaped | per-dest idle reaper added (reads `last_active`, per-dest cancel token) |
| M8 | No rate limiting on `/api/login` | per-source-IP throttle (10 fails / 60 s → HTTP 429 + `Retry-After`) |

---

## Outstanding findings (not yet addressed)

### 🔴 HIGH

#### H1 — Upstream HTTPS server-certificate verification fully disabled
`src/tls.rs:88-111`, `src/tls.rs:212-262` · CWE-295

Both outbound TLS connectors install `AcceptAnyServerCert`, whose
`verify_server_cert` / `verify_tls12_signature` / `verify_tls13_signature` all
return success unconditionally — no chain, expiry, or hostname/SAN check. This is
wired into the HTTP proxy's plain-forwarding path (`src/http.rs:147-155`) where the
proxy itself terminates upstream TLS for an absolute-form `https://` request.

- **Impact:** an active on-path attacker between the proxy and the upstream can
  present any certificate and MITM all plain-forwarded HTTPS (read/modify bodies,
  steal cookies/credentials). The common browser `CONNECT` path is *not* affected
  (tunnelled opaquely; the client verifies end-to-end).
- **Recommendation:** use rustls's webpki verifier with a real root store for
  upstream connections (verify chain + SNI hostname). If private-CA upstreams are
  needed, add an explicit per-proxy CA/pin, and only fall back to
  accept-any behind an explicit, UI-surfaced `insecure_skip_verify` opt-in
  (consistent with permissive-with-warnings). Never blanket-accept by default.
- **Why deferred:** changes outbound TLS trust semantics for existing deployments
  that may rely on private-CA upstreams; needs a config surface + migration note.

### 🟠 MEDIUM

#### M2 — `admin_network` CIDR enforced only at login, not per request
`src/manager.rs` `AdminAuth::check` vs `valid` · CWE-284

The per-admin network restriction is checked once at login; `require_auth` only
verifies session-set membership and never re-checks the source IP. A captured
token (e.g. sniffed over cleartext HTTP) replays from any network for its lifetime.

- **Recommendation:** bind each session to its admin + source IP/CIDR at creation
  and re-validate the CIDR on every request in `require_auth`.

#### M4 — Header-override value/key injected verbatim (CRLF injection)
`src/http.rs:191-203` · CWE-113

Configured header overrides are concatenated into the upstream request with no
CR/LF/NUL neutralization; only empty keys are filtered (`src/api.rs`). A `\r\n` in
a value injects headers / smuggles a request line into every plain-HTTP request the
proxy forwards.

- **Recommendation:** reject/strip `\r` `\n` `\0` in key and value (and `:` in
  keys) at the API boundary and defensively in `http.rs` before writing upstream.
- **Note:** writable only by an admin (unauthenticated only when the admin is left
  open), who already controls the proxy — hence medium, not high.

#### M6 — Idle timeout disabled by default (accepted by design)
`src/relay.rs:133-148` · CWE-400 — **won't-fix / mitigated**

TCP relays default to no idle reaping (`idle_timeout_secs = None`). Imposing a
default idle timeout would break legitimate long-idle TCP (SSH-over-proxy,
long-poll), which contradicts the permissive-with-warnings philosophy. The
idle-hold DoS is now bounded by the `max_connections` cap (M5) and the handshake
timeout (H4). Operators who want idle reaping can set `idle_timeout_secs`.

### 🟡 LOW

| ID | Title | Where | Recommendation |
|----|-------|-------|----------------|
| L1 | Plaintext admin password compared with `==` (timing oracle) | `src/manager.rs:141-152` | constant-time compare on the plaintext branch (partially mitigated by M8) |
| L2 | Sessions never expire server-side | `src/manager.rs` session set | record issue time per token; expire by max-age + idle; prune |
| L3 | Network-deny login error leaks credential validity | `src/manager.rs:191-201` | return a single uniform error for bad creds and off-network |
| L4 | `admin_user` without `admin_password` silently leaves admin open | `src/main.rs` `build_admins` | error or warn loudly when a username is set without a password |
| L5 | No CSRF token (relies solely on `SameSite=Strict`) | `src/api.rs` | add a double-submit CSRF token for state-changing routes |
| L6 | Connection history grows unbounded in RocksDB; query limit unbounded | `src/storage.rs:55-88` | cap/TTL history; clamp the `limit` query param |
| L7 | `accept_loop` busy-loops on persistent `accept()` errors | `src/manager.rs` accept loop | back off / bail after repeated errors |
| L8 | No clickjacking protection / CSP on the admin page | `src/api.rs` `index` | add `Content-Security-Policy` + `X-Frame-Options: DENY` |
| L9 | HTTP/HTTPS proxy has no internal-destination guard (SSRF) | `src/http.rs:108-208` | optional `is_internal_dest` guard like the UDP path's `udp_allow_private` |
| L10 | WebSocket `?target=` destination unfiltered (SSRF) | `src/ws_proxy.rs:111-142` | same internal-dest guard for the WS tunnel |
| L11 | Proxy Basic-auth compared in non-constant time | `src/http.rs:76-89` | constant-time compare |
| L12 | Secrets stored plaintext, no file-permission hardening | `src/storage.rs` | restrict `data_dir` perms (0700) and warn; document at-rest exposure |
| L13 | Pidfile written to a predictable path, non-exclusive, follows symlinks | `src/main.rs:415-420` | exclusive create / `O_NOFOLLOW`, or restrict `data_dir` perms |
| L14 | RFC 1929 SOCKS user/pass compared in non-constant time | `src/socks5.rs:136-144` | constant-time compare (partially mitigated for online attacks by M8) |
| L15 | UDP associate first-datagram pin keys only on source IP | `src/socks5.rs:377-389` | pin the full 2-tuple, or document the shared-NAT-host limitation |

### ⚪ INFO

| ID | Title | Where |
|----|-------|-------|
| I1 | Duplicate config keys silently last-wins; cross-form admin key collisions unvalidated | `src/main.rs` properties parser / `build_admins` |

---

## Refuted (verified false positives)

These were filed by a finder but dismissed on adversarial verification; recorded so
they are not re-investigated:

1. **CSWSH (WebSocket upgrade has no `Origin` check)** — `SameSite=Strict` already
   blocks cross-site-initiated handshakes in current browsers; an `Origin`
   allow-list would be defense-in-depth, not a fix for a reachable bug.
2. **PKCS#12 passwords held as plaintext `String` in memory** — the same secrets
   are persisted in plaintext in RocksDB by design; no extra flaw (not logged).
3. **HTTP request smuggling via lenient head parsing** — the relay opens a fresh
   upstream connection per request and forces `Connection: close`; with no
   connection reuse there is no second request to smuggle into.
4. **`esc()` doesn't escape `'` (generic)** — the only truly low-trust field
   (`dst_addr`) is only ever rendered in HTML-text context. (The concrete exploit
   paths were the H2/H3 `onclick` sinks, which *are* fixed.)
5. **`stop` kills every process sharing the executable name** — intended and
   documented behavior; requires local same-user code execution (outside the
   network threat boundary).
6. **Timing oracle on plaintext admin password (process-daemon report)** — the
   `&&` short-circuit makes username existence the dominant channel and `==`
   lowers to `memcmp`; tracked as L1 with negligible real-world impact.
7. **Properties parser ignores inline comments / quoting** — matches the real Java
   `.properties` spec; operator-controlled input, fails closed.
8. **Operator-supplied paths not canonicalized** — trusted operator input, no
   attacker surface; a footgun, not a vulnerability.
