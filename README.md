# sn-proxy

A multi-instance, multi-protocol **proxy server** written in Rust with a
realtime web admin. Everything runs on a single Tokio runtime.

## Supported protocols

| Protocol      | Notes                                                          |
|---------------|----------------------------------------------------------------|
| `socks5`      | RFC 1928, optional username/password auth (RFC 1929)           |
| `http`        | `CONNECT` tunnelling + plain HTTP forwarding, optional Basic auth |
| `https`       | HTTP proxy wrapped in TLS (config cert, per-proxy PKCS#12, or auto self-signed) |
| `shadowsocks` | AEAD (`aes-256-gcm`, `aes-128-gcm`, `chacha20-ietf-poly1305`)  |
| `tcp`         | Plain TCP forwarder to a fixed `host:port` destination         |
| `udp`         | Plain UDP forwarder to a fixed `host:port` destination         |
| `websocket`   | WebSocket tunnel (RFC 6455) to a fixed `host:port` destination |
| `turn`        | TURN relay (RFC 8656) for WebRTC — UDP/TCP/TLS, REST-API auth  |
| `smtp`        | SMTP egress relay — accepts submission from your MTA, resolves MX, delivers from this host's IP |

Each proxy also has optional advanced tuning: **TCP keep-alive** interval,
**idle timeout** (drop connections with no traffic), **connect timeout**
(when dialing the destination), and a **max active connections** cap (new
connections beyond it are refused at accept time; default `8888`, `0` =
unlimited).

### HTTP / HTTPS extras

`http` and `https` proxies support extra configuration, all editable from the
web admin:

- **Header overrides** — inject/replace request headers (key/value pairs) on
  plain-forwarded HTTP requests.
- **Client mTLS** — upload a PKCS#12 (`.p12`/`.pfx`) client identity (with
  password, and optional entry alias / entry password). When forwarding to an
  `https://` destination that identity is presented, satisfying servers that
  require mutual TLS.
- **HTTPS listener TLS** — an `https` proxy can use its own PKCS#12 keystore
  for the listener certificate instead of the global one, and can require
  connecting clients to present a certificate (**mTLS**) validated against an
  uploaded PKCS#12 truststore.

### TURN relay

A `turn` proxy is a TURN server (RFC 8656) for WebRTC. It differs from every
other protocol here: it does not forward to a destination you configure, it
**allocates a public relay address** per authenticated client and relays between
that address and the peers the client asks for.

- **One proxy, up to three listeners** — UDP and TCP share the listen address
  (3478 by convention); `turns:` (TLS) takes its own, and reuses the same PKCS#12
  keystore mechanism as an `https` proxy.
- **Auth is the TURN REST API only** (coturn's `static-auth-secret` scheme):
  `username = "<unix_expiry>:<userid>"`,
  `password = base64(HMAC-SHA1(secret, username))`. The web admin can mint a test
  credential for you; the secret is never sent back to the browser once saved.
- **A realm is required.** Browsers only recompute their credential hash when the
  realm *changes* and initialise it empty, so an empty realm fails every
  allocation with no useful error.
- **The relay IP must be concrete**, never a wildcard: ICE requires a
  connectivity-check response to arrive from the address the request was sent to,
  and a wildcard bind lets the kernel choose per route.
- **Reserve the relay port range** at the OS level. It defaults to
  `49152–51199` — narrower than the RFC's recommendation, which collides exactly
  with the Windows dynamic port range and would let a flood starve every other
  proxy in the process of ephemeral ports.
- `turns:` needs a **real, publicly-trusted certificate** whose SAN matches the
  hostname clients use. Browsers validate it against the OS trust store with no
  way to bypass it, so the built-in self-signed fallback is always rejected.

REST credential expiry is an **Allocate-only** gate, matching coturn and LiveKit
1.12: a Refresh / CreatePermission / ChannelBind on a live allocation still
verifies HMAC and the userid, but does not re-check the timestamp, so a call
longer than the REST TTL does not drop media. The remaining deliberate
difference from coturn is that the per-user quota and the anti-hijack check
compare only the `userid` half of the username — the timestamp prefix rotates,
so comparing the whole string would kill live allocations whenever a client
re-derives credentials.

### SMTP egress relay

An `smtp` proxy is a **thin outbound relay**, not a mailbox: it accepts an SMTP
session from a trusted client MTA (e.g. your mail server's smarthost route),
resolves each recipient domain's MX records and delivers the message by opening
a fresh connection to the real MX **from this host's own public IP**. That is
the entire reason it exists — a port-forward keeps the client's source IP, while
a relay originates a new connection and therefore uses *this* machine's
PTR/SPF identity.

- **No queue of its own.** The upstream MX reply — including rejects like a
  `550` rDNS failure — is relayed back to the client verbatim, so the client
  MTA keeps queue, retry and bounce (DSN) handling.
- **`smtp.helo_name` is required** and must be the hostname whose PTR record
  points back at this relay's public IP (forward-confirmed rDNS). Gmail rejects
  delivery without it.
- **Auth**: the `auth` username/password becomes the `AUTH LOGIN`/`PLAIN`
  credential. It is **mandatory on a public or wildcard bind** (refused at save
  time — an open relay is abuse-bait) and optional, with a warning, on private
  binds (loopback/RFC1918/tailnet).
- **TLS**: client-side `STARTTLS` is offered when a `server_p12` keystore (or
  the global `tls_cert`) is configured. Upstream STARTTLS is opportunistic by
  default with certificates verified against the Mozilla root store;
  `require_starttls` turns a missing offer into a 4xx retry instead of
  cleartext delivery.
- **Recipients are pooled per domain** — one upstream connection per recipient
  domain carries the session's `MAIL FROM` + its RCPTs; `DATA` is buffered
  (default cap 35 MiB) and replayed per domain. If any domain rejects, the
  client sees that failure and retries.
- **SSRF guard**: MX/A records resolving to loopback/RFC1918/reserved are
  refused unless `smtp.allow_private` is on.
- **History**: connection history shows the resolved domains as
  `mx:example.com,…`. It is connection-level accounting, not a per-message
  audit log.

### Connection control

- **Terminate** any in-flight connection from the live table.
- **Block** a source `IP` or `IP:port`: it is refused at accept time on every
  proxy, and matching live connections are dropped immediately. The blocklist
  is persisted and managed from the "Blocklist" panel.

## Features

- **Eight proxy protocols** — pick one per proxy instance (see table above)
- **Web admin** to create, edit, start/stop and delete multiple proxies — each
  with its own protocol, listen address and credentials
- **Realtime monitoring** over a websocket (built on
  [`fastwebsockets`](https://github.com/denoland/fastwebsockets)): live list of
  open connections per proxy with source IP, destination and bytes
  sent/received
- **PROXY protocol v1** on the TCP forwarder (`send_proxy_protocol`, off by
  default) — announces the original client address to the destination. Without
  it the destination only ever sees this proxy's address, which silently breaks
  everything that reasons about the client IP: SPF checks on a relayed SMTP
  port, IP allow/deny lists, per-client rate limits, access logs. The header is
  written as the **first bytes** of the upstream connection, so the destination
  must be configured to expect it from this proxy's address — turning it on
  against a server that does not parse it drops every connection
- **Connection history** of closed connections, persisted in **RocksDB**
- **Host resource monitor** — a toggled side panel with realtime CPU, RAM, file
  descriptor/handle and network-throughput charts plus a per-interface ifstat
  table. Demand-driven: a single collector samples the host once a second only
  while at least one viewer is watching, and fans the sample out to all of them.
  Linux reads `/proc`; Windows uses Win32 (`GetSystemTimes`,
  `GlobalMemoryStatusEx`, `GetPerformanceInfo`, `GetIfTable2`); other platforms
  show "unsupported"
- **HTTP API** built on **axum**

## Running

```sh
cargo run --release
```

Then open the web admin at <http://localhost:8080>.

Command-line options:

| Option                          | Default        | Description                                                                 |
|----------------------------------|----------------|-----------------------------------------------------------------------------|
| `-c`, `--config <FILE>`          | —              | Properties config file (see below)                                          |
| `-p`, `--port <[HOST:]PORT>`     | `0.0.0.0:8080` | Web admin address. A bare port binds every interface; `HOST:PORT` binds one  |
| `-d`, `--data-dir <DIR>`         | `data`         | RocksDB data directory                                                      |
| `-m`, `--mode <daemon\|foreground>` | `daemon`    | Run backgrounded (default) or attached to the console (see *Run mode*)      |
| `-h`, `--help`                   | —              | Print help and exit                                                         |

`-p` / `-d` / `-m` override the config file.

```sh
cargo run --release -- --config config.properties
cargo run --release -- --port 127.0.0.1:9991 --data-dir /var/lib/sn-proxy
# stay attached to the console (handy in development):
cargo run --release -- --mode foreground
```

### Config file

A `key=value` properties file (`#` / `!` comments). Command-line `-p` / `-d`
override it. See [`config.example.properties`](config.example.properties).

| Key              | Description                                                      |
|------------------|------------------------------------------------------------------|
| `port`           | Web admin port or `HOST:PORT`                                    |
| `data_dir`       | RocksDB data directory                                           |
| `tls_cert`       | PEM certificate for the `https` proxy (else a self-signed one)   |
| `tls_key`        | PEM private key for the `https` proxy                            |
| `admin_user`     | Web admin login username — setting it (with a password) enables login |
| `admin_password` | Web admin login password — plaintext or an `$argon2` hash (see *Admin passwords*) |
| `admin_network`  | Restrict that admin's login to a CIDR, e.g. `192.168.1.0/24`     |
| `admin.<NAME>.password` | An additional admin account (multi-admin form)            |
| `admin.<NAME>.network`  | That admin's allowed CIDR (optional)                      |
| `admin_https`    | `true` if the admin is reached over HTTPS — marks the session cookie `Secure` (default `false`) |
| `mode`           | `daemon` (background, default) or `foreground` (see *Run mode*)  |
| `log_file`       | Daily-rotated log file; off when unset (see *Logging*)           |

Configuring at least one admin makes the web admin require sign-in (cookie
session); otherwise it is open. Each admin may have its own `network` CIDR —
sign-in is then only accepted from a client IP inside that range. Admins
without a network may sign in from anywhere. `RUST_LOG` (default
`sn_proxy=info`) controls the log filter.

Proxy configs are persisted; proxies that were running are auto-started on the
next launch.

### Admin passwords

An `admin_password` (or `admin.<NAME>.password`) may be either plaintext or an
**argon2** PHC hash — a string beginning with `$argon2` such as
`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. When the stored value is a hash
it is verified with argon2 at login (the variant and cost parameters are read
from the hash); otherwise the comparison is plaintext. Plaintext still works but
logs a warning at startup — prefer a hash. Generate one with any argon2 tool,
e.g. Python's `argon2-cffi`:

```sh
python -c "from argon2 import PasswordHasher as P; print(P().hash('your-password'))"
```

### Run mode

`mode` (or `-m` / `--mode`) selects how the process runs. It defaults to
**`daemon`**: on startup the process re-spawns itself detached from the console,
prints `started in background, pid <N>` (also written to
`<data_dir>/sn-proxy.pid`) and the foreground command returns immediately. Before
backgrounding, the parent does a pre-flight bind of the web-admin port, so a
port-in-use error is reported on the console instead of vanishing into the
background.

Stop every running background instance with **`sn-proxy stop`**. It matches
processes by executable name (so it also catches orphans from earlier runs that
the single-entry pidfile no longer tracks), skips the stop command's own
process, force-terminates the rest, and removes `<data_dir>/sn-proxy.pid`. Pass
the same `-d`/`--data-dir` (or `-c`) you started with so the right pidfile is
cleaned; the kill itself works regardless of pidfile state. To stop a single
instance instead, use the OS with its pid (`taskkill /PID <N>` on Windows,
`kill <N>` on Unix).

Use `mode=foreground` (or `--mode foreground`) to stay attached — the process
runs in the current console and logs to stdout, which is what you usually want
during development and under a service manager (systemd, nssm, …).

> Note: because the default is daemon, a plain `cargo run` now detaches and
> returns. Use `cargo run -- --mode foreground` to keep it in the foreground.

### Logging

By default logs go to stdout. Set `log_file` to also write them to a file that
**rotates daily** (old files are kept, never auto-deleted). The value is a
directory or a file path:

- a value ending in a path separator (`logs/`) is a directory; files are named
  `sn-proxy.<YYYY-MM-DD>` inside it;
- otherwise the last path component is the filename prefix
  (`logs/proxy.log` → `logs/proxy.log.<YYYY-MM-DD>`).

The directory is created if missing. In **foreground** mode logs are written to
both the file and stdout; in **daemon** mode the console is detached, so a
daemon with no `log_file` discards its logs (a warning is printed before it
backgrounds). `RUST_LOG` (default `sn_proxy=info`) filters file output too.

## Using a proxy

```sh
# SOCKS5
curl --socks5 alice:secret@127.0.0.1:1080 https://example.com
# HTTP / HTTPS proxy
curl -x http://alice:secret@127.0.0.1:1081 https://example.com
curl -x https://127.0.0.1:1082 --proxy-insecure https://example.com
# Shadowsocks: point any Shadowsocks client at the listen address,
# using the configured cipher and password.
```

## HTTP API

| Method & path                       | Description                       |
|--------------------------------------|-----------------------------------|
| `GET    /api/session`                | Whether login is required / active |
| `POST   /api/login`                  | Sign in, sets a session cookie    |
| `POST   /api/logout`                 | Sign out                          |
| `GET    /api/proxies`                | List proxies + live status        |
| `POST   /api/proxies`                | Create a proxy                    |
| `POST   /api/proxies/{id}`           | Update a proxy                    |
| `DELETE /api/proxies/{id}`           | Delete a proxy and its history    |
| `POST   /api/proxies/{id}/start`     | Start a proxy                     |
| `POST   /api/proxies/{id}/stop`      | Stop a proxy                      |
| `GET    /api/proxies/{id}/history`   | History page (`?offset=&limit=`)  |
| `DELETE /api/proxies/{id}/history`   | Delete all history for a proxy    |
| `POST   /api/proxies/{id}/conns/{cid}/kill` | Terminate one live connection |
| `GET    /api/blocklist`              | List blocked source addresses     |
| `POST   /api/blocklist`              | Block an address (`{"addr": …}`)  |
| `DELETE /api/blocklist`              | Unblock an address (`{"addr": …}`) |
| `GET    /ws`                         | Websocket monitoring feed         |
| `GET    /ws/resources`               | Websocket host-resource feed (demand-driven) |

## Architecture

| Module           | Responsibility                                          |
|------------------|---------------------------------------------------------|
| `socks5.rs`      | SOCKS5 handshake, auth, CONNECT relay                   |
| `http.rs`        | HTTP/HTTPS proxy (CONNECT, forwarding, header overrides, client mTLS) |
| `shadowsocks.rs` | Shadowsocks AEAD server                                 |
| `tcp.rs`         | Plain TCP forwarder                                     |
| `udp.rs`         | Plain UDP forwarder                                     |
| `ws_proxy.rs`    | WebSocket tunnelling proxy (RFC 6455)                   |
| `stun.rs`        | STUN codec (RFC 8489) — pure, pinned to the RFC 5769 vectors |
| `turn_auth.rs`   | TURN REST credentials and the stateless nonce           |
| `turn_alloc.rs`  | TURN allocation/permission/channel state and the relay-port pool |
| `turn.rs`        | TURN listeners, dispatch and allocation lifecycle       |
| `turn_relay.rs`  | The relayed transport address — an opaque byte pipe     |
| `turn_rrl.rs`    | Fixed-size response rate limiter for the TURN listeners |
| `tls.rs`         | TLS acceptors/connectors: PEM, self-signed and PKCS#12  |
| `relay.rs`       | Connection tracking, byte counting, keep-alive, timeouts |
| `manager.rs`     | Proxy lifecycle, protocol dispatch, connection registry |
| `storage.rs`     | RocksDB persistence (configs + history)                 |
| `api.rs`         | axum HTTP routes                                        |
| `ws.rs`          | fastwebsockets monitoring feed                          |
| `monitor.rs`     | Snapshot/event payloads                                 |
| `model.rs`       | Shared data types                                       |

## Security

A security audit of the codebase (findings, what is fixed, and the known
outstanding issues) is recorded in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md). Note
in particular that the web admin is open by default — configure an admin account
(and `admin_https` behind TLS) before exposing it — and that the upstream-TLS
verification gap (H1) is still outstanding.
