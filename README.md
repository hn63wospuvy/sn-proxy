# sn-proxy

A multi-instance **SOCKS5 proxy server** written in Rust with a realtime web
admin. Everything runs on a single Tokio runtime.

## Features

- **SOCKS5 proxy** (RFC 1928) with optional username/password auth (RFC 1929)
- **Web admin** to create, edit, start/stop and delete multiple proxies — each
  with its own listen address and credentials
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

| Option              | Default | Description                                      |
|---------------------|---------|--------------------------------------------------|
| `-p`, `--port`      | `8080`  | Web admin port; the admin always binds `0.0.0.0` |
| `-d`, `--data-dir`  | `data`  | RocksDB data directory                           |
| `-h`, `--help`      | —       | Print help and exit                              |

```sh
# custom port and data directory
cargo run --release -- --port 9090 --data-dir /var/lib/sn-proxy
```

`RUST_LOG` (default `sn_proxy=info`) still controls the log filter.

Proxy configs are persisted; proxies that were running are auto-started on the
next launch.

## Using a proxy

After creating a proxy listening on e.g. `0.0.0.0:1080` with user `alice`:

```sh
curl --socks5 alice:secret@127.0.0.1:1080 https://example.com
```

## HTTP API

| Method & path                       | Description                       |
|--------------------------------------|-----------------------------------|
| `GET    /api/proxies`                | List proxies + live status        |
| `POST   /api/proxies`                | Create a proxy                    |
| `POST   /api/proxies/{id}`           | Update a proxy                    |
| `DELETE /api/proxies/{id}`           | Delete a proxy and its history    |
| `POST   /api/proxies/{id}/start`     | Start a proxy                     |
| `POST   /api/proxies/{id}/stop`      | Stop a proxy                      |
| `GET    /api/proxies/{id}/history`   | Closed-connection history         |
| `GET    /ws`                         | Websocket monitoring feed         |

## Architecture

| Module        | Responsibility                                          |
|---------------|---------------------------------------------------------|
| `socks5.rs`   | SOCKS5 handshake, auth, CONNECT relay, byte counting    |
| `manager.rs`  | Proxy lifecycle, live connection registry, broadcasting |
| `storage.rs`  | RocksDB persistence (configs + history)                 |
| `api.rs`      | axum HTTP routes                                        |
| `ws.rs`       | fastwebsockets monitoring feed                          |
| `monitor.rs`  | Snapshot/event payloads                                 |
| `model.rs`    | Shared data types                                       |
