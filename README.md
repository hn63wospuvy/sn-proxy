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
| `websocket`   | WebSocket tunnel (RFC 6455) to a fixed `host:port` destination |

Each proxy also has optional advanced tuning: **TCP keep-alive** interval,
**idle timeout** (drop connections with no traffic), and **connect timeout**
(when dialing the destination).

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

### Connection control

- **Terminate** any in-flight connection from the live table.
- **Block** a source `IP` or `IP:port`: it is refused at accept time on every
  proxy, and matching live connections are dropped immediately. The blocklist
  is persisted and managed from the "Blocklist" panel.

## Features

- **Six proxy protocols** — pick one per proxy instance (see table above)
- **Web admin** to create, edit, start/stop and delete multiple proxies — each
  with its own protocol, listen address and credentials
- **Realtime monitoring** over a websocket (built on
  [`fastwebsockets`](https://github.com/denoland/fastwebsockets)): live list of
  open connections per proxy with source IP, destination and bytes
  sent/received
- **Connection history** of closed connections, persisted in **RocksDB**
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
`<data_dir>/sn-proxy.pid`) and the foreground command returns immediately. Stop
it with the OS using that pid (`taskkill /PID <N>` on Windows, `kill <N>` on
Unix). Before backgrounding, the parent does a pre-flight bind of the web-admin
port, so a port-in-use error is reported on the console instead of vanishing
into the background.

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

## Architecture

| Module           | Responsibility                                          |
|------------------|---------------------------------------------------------|
| `socks5.rs`      | SOCKS5 handshake, auth, CONNECT relay                   |
| `http.rs`        | HTTP/HTTPS proxy (CONNECT, forwarding, header overrides, client mTLS) |
| `shadowsocks.rs` | Shadowsocks AEAD server                                 |
| `tcp.rs`         | Plain TCP forwarder                                     |
| `ws_proxy.rs`    | WebSocket tunnelling proxy (RFC 6455)                   |
| `tls.rs`         | TLS acceptors/connectors: PEM, self-signed and PKCS#12  |
| `relay.rs`       | Connection tracking, byte counting, keep-alive, timeouts |
| `manager.rs`     | Proxy lifecycle, protocol dispatch, connection registry |
| `storage.rs`     | RocksDB persistence (configs + history)                 |
| `api.rs`         | axum HTTP routes                                        |
| `ws.rs`          | fastwebsockets monitoring feed                          |
| `monitor.rs`     | Snapshot/event payloads                                 |
| `model.rs`       | Shared data types                                       |
