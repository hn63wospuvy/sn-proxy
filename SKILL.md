---
name: sn-proxy-admin-api
description: Use when an agent must create, update, start/stop, block, inspect or reconcile sn-proxy proxy instances over the HTTP admin API (`/api/proxies`, `/api/blocklist`, `/ws`) instead of clicking the web admin — covers login/session, the full ProxyForm field reference (socks5/http/https/shadowsocks/tcp/websocket/udp/turn/smtp), per-protocol required fields, the full-replace update trap, and error recovery.
---

# sn-proxy admin API

Drive an sn-proxy instance programmatically. Everything the web admin can do is
one of the JSON routes below; the UI has no private endpoints.

Default base URL: `http://127.0.0.1:8080` (set by `-p/--port` or `port=` in the
properties file — a bare port means `0.0.0.0`). All examples use
`$BASE=http://127.0.0.1:8080`.

## 0. Golden rules

1. **Log in first, keep the cookie.** Every `/api/*` route except
   `/api/session`, `/api/login`, `/api/logout` and `/` is behind a session check.
2. **`POST /api/proxies/{id}` is a full replace, not a patch.** Any field you
   omit reverts to its default — except the PKCS#12 groups and
   `turn.static_secret`, which are tri-state. See §5.
3. **`GET /api/proxies` never returns secrets.** No proxy password, no
   Shadowsocks password, no keystore password, no TURN `static_secret`
   (`has_turn_secret` instead). A blind read-modify-write wipes them. Keep your
   own desired-state, or re-send the secrets. See §5.
4. **Create leaves the proxy stopped.** A new proxy has `enabled: false` and is
   not listening until you `POST /api/proxies/{id}/start`.
5. **Nothing is unique.** Two proxies may share a name *and* a listen address;
   the collision only surfaces as a bind error at start. Reconcile by listing
   first (§6) or you will create duplicates on every run.
6. **Never print secrets.** `POST /api/proxies` echoes back the full
   `ProxyConfig` *including* passwords, base64 keystores and
   `turn.static_secret`. Do not log the response body verbatim.

## 1. Routes

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `GET /api/session` | — | `{"auth_required":bool,"logged_in":bool}` | Open. Use as the readiness/health probe. |
| `POST /api/login` | `{"username","password"}` | `200`, `Set-Cookie: sn_session=…` | Empty body. |
| `POST /api/logout` | — | `200` | Revokes the token. |
| `GET /api/proxies` | — | `200` `[ProxySnapshot]` | Status + live connections, **no secrets**. |
| `POST /api/proxies` | `ProxyForm` | `200` `ProxyConfig` (has `id`) | Created stopped. |
| `POST /api/proxies/{id}` | `ProxyForm` | `200` `ProxyConfig` | Full replace; restarts if running. |
| `DELETE /api/proxies/{id}` | — | `204` | Also deletes its history. |
| `POST /api/proxies/{id}/start` | — | `200` | Idempotent; binds the socket. |
| `POST /api/proxies/{id}/stop` | — | `200` | Idempotent; kills live connections. |
| `GET /api/proxies/{id}/history` | `?offset=&limit=` | `{"records":[…],"offset","limit","has_more"}` | `limit` default 20. |
| `DELETE /api/proxies/{id}/history` | — | `204` | |
| `POST /api/proxies/{id}/conns/{cid}/kill` | — | `200` | `cid` from a snapshot's `active_connections[].id`. |
| `GET /api/blocklist` | — | `200` `["1.2.3.4", …]` | Global, sorted. |
| `POST /api/blocklist` | `{"addr":"…"}` | `200` | `IP` or `IP:port`. Drops matching live conns. |
| `DELETE /api/blocklist` | `{"addr":"…"}` | `200` | |
| `GET /api/proxies/{id}/blocklist` | — | `200` `[String]` | Per-proxy list (not in the README). |
| `POST /api/proxies/{id}/blocklist` | `{"addr":"…"}` | `200` | |
| `DELETE /api/proxies/{id}/blocklist` | `{"addr":"…"}` | `200` | |
| `GET /ws` | — | websocket | Snapshot on connect, then one per second. |
| `GET /ws/resources` | — | websocket | Host CPU/RAM/fd/net; first sample after ~1 s. |

Errors from the handlers are `400` with `{"error":"<message>"}`. A body that
fails to deserialize is rejected by axum *before* the handler, so it comes back
as a plain-text `4xx` (usually `422`) with no `error` key — treat a non-JSON
error body as "my request shape is wrong", not "the server is broken".

## 2. Login

```bash
BASE=http://127.0.0.1:8080
JAR=$(mktemp)

# Is a login even required? Open instances answer auth_required=false.
curl -s "$BASE/api/session"
# {"auth_required":true,"logged_in":false}

curl -s -c "$JAR" -X POST "$BASE/api/login" \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"…"}'

# every protected call from now on:
curl -s -b "$JAR" "$BASE/api/proxies"
```

PowerShell:

```powershell
$Base = 'http://127.0.0.1:8080'
$S = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod "$Base/api/login" -Method Post -WebSession $S `
  -ContentType 'application/json' `
  -Body (@{ username='admin'; password='…' } | ConvertTo-Json)
Invoke-RestMethod "$Base/api/proxies" -WebSession $S
```

Session facts that change agent behaviour:

- The cookie is `sn_session=<uuid>`, `HttpOnly; SameSite=Strict; Path=/;
  Max-Age=86400`. `Secure` is added only when the server was started with
  `admin_https=true` — over plain HTTP a `Secure` cookie would never be sent
  back, so if login "succeeds" but every call 401s, that mismatch is the cause.
- **Sessions live in memory.** A server restart invalidates every token. On a
  `401 {"error":"login required"}`, log in again once and retry — do not treat
  it as a fatal error.
- **Brute-force throttle: 10 failed logins per source IP per 60 s → `429`** with
  a `Retry-After` header. Never retry a bad password in a loop; you will lock
  the IP out of a working password for a minute. Read `Retry-After` and wait.
- `"login is not allowed from your network"` means that admin has an
  `admin_network` CIDR that excludes your IP. Different credentials will not
  help; you need to call from an allowed address.

## 3. `ProxyForm` — the create/update body

Only `name` and `listen_addr` are structurally required; `protocol` defaults to
`socks5`.

| Field | Type | Applies to | Semantics |
|---|---|---|---|
| `name` | string | all | Required. No control characters, ≤200 chars (it is rendered in the admin UI). |
| `protocol` | enum | all | `socks5`\|`http`\|`https`\|`shadowsocks`\|`tcp`\|`websocket`\|`udp`\|`turn`\|`smtp`. Omitted ⇒ `socks5`. |
| `listen_addr` | string | all | Required, e.g. `0.0.0.0:1080`. Not validated until start. TURN UDP/TCP share this address (3478 by convention). |
| `auth` | `{username,password}` | socks5, http, https, websocket, smtp | Omitted, or `username` exactly `""` ⇒ no auth. **Ignored for `turn`** — TURN authenticates with the REST API only (`turn.static_secret`). For `smtp` it becomes the `AUTH LOGIN`/`PLAIN` credential — **required when the listen address is public/wildcard** (else 400 at save: an open relay). |
| `ss_method` | string | shadowsocks | Required: `aes-128-gcm`, `aes-256-gcm` or `chacha20-ietf-poly1305`. |
| `ss_password` | string | shadowsocks | Required, non-empty. |
| `forward_to` | `host:port` | tcp, websocket, udp | **Required for these three.** Ignored elsewhere (TURN has no fixed destination). |
| `keepalive_secs` | int | all | `0`/omitted ⇒ off. |
| `idle_timeout_secs` | int | all | `0`/omitted ⇒ off (udp applies its own 60 s default). |
| `connect_timeout_secs` | int | all | `0`/omitted ⇒ off. |
| `max_connections` | int | all | Omitted/`null` ⇒ **8888**; `0` ⇒ **unlimited**; `n` ⇒ `n`. Passed through verbatim — `0` is not coerced. On `turn`, `0` is still stored but the allocation cap is clamped to the relay port-range size. |
| `send_proxy_protocol` | bool | tcp | PROXY protocol v1 header. Default `false`. See §7. |
| `override_headers` | `[{key,value}]` | http, https | Injected on plain-forwarded HTTP. Blank `key` entries are dropped. |
| `client_p12` | base64 | http, https | Client mTLS identity toward the destination. |
| `client_p12_password` | string | http, https | |
| `client_p12_alias` | string | http, https | Keystore entry; empty ⇒ first private key. |
| `client_p12_entry_password` | string | http, https | Rarely needed. |
| `server_p12` | base64 | https, turn, smtp | Listener keystore for `https`, for TURN's `turns:` (TLS) transport, and for the SMTP client's `STARTTLS`; absent ⇒ the global `tls_cert`/`tls_key` or a self-signed cert. Browsers reject that fallback on `turns:` — see §7. |
| `server_p12_password` | string | https, turn, smtp | |
| `server_truststore_p12` | base64 | https | CA set validating client certs. |
| `server_truststore_password` | string | https | |
| `mtls_required` | bool | https | Require a client certificate. Default `false`. Forced off for `turn` (`turns:` clients never present one); meaningless for `smtp`. |
| `udp_associate_enabled` | bool | socks5 | **Omitted ⇒ `true`.** `false` makes the server reply `0x07` to `CMD=0x03`. |
| `udp_allow_private` | bool | socks5 | Allows RFC1918/internal UDP destinations. **SSRF risk** — see §7. |
| `udp_bind_addr` | string | socks5 | Relay socket bind; default = listener IP. |
| `udp_advertise_ip` | string | socks5 | IP reported in `BND.ADDR` (NAT / multi-homed). |
| `udp_max_datagram` | int | socks5 | Default 64 KiB. `0` ⇒ default. |
| `udp_max_dests` | int | socks5 | `0`/omitted ⇒ unlimited. |
| `turn` | object | turn | Nested TURN settings. Omitted ⇒ empty-realm / no-secret defaults, which **fail validate**. See the table below. Always send the whole object on update — only `static_secret` is tri-state. |
| `smtp` | object | smtp | Nested SMTP-relay settings. Omitted ⇒ empty `helo_name`, which **fails validate**. See the table below. |

Not settable through this body: `id` (server-generated UUID), `enabled` (use
start/stop), `blocklist` (use the blocklist routes).

Base64 fields take **plain standard base64 of the raw `.p12` bytes**, trimmed —
no `data:` prefix, no PEM armor:

```bash
base64 -w0 client.p12                              # Linux/Git Bash
```
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('client.p12'))
```

### `turn` object

A `turn` proxy is a TURN server (RFC 8656): it allocates a relay address per
authenticated client. It does not use `auth` or `forward_to`.

| Field | Type | Semantics |
|---|---|---|
| `transports` | `string[]` | Any subset of `udp`, `tcp`, `tls`. Omitted ⇒ `["udp","tcp"]`. Empty ⇒ 400. An unknown value ⇒ 400 (not silently ignored). |
| `tls_listen` | `host:port` | **Required when `tls` is selected.** Independent of `listen_addr` (5349 by convention). |
| `realm` | string | **Required.** 1–127 printable ASCII, no space / `"` / `'` / `\`. An empty realm makes browsers fail every allocation (libwebrtc only recomputes its hash when the realm *changes*, and starts it empty). |
| `static_secret` | string | REST-API minting key, **≥16 bytes**. Snapshot never returns it. Tri-state on update — see §5. Create must send it; omitting it is a 400, not "no auth". |
| `relay_ip` | string | Concrete IP the relay sockets bind. Required at **start** (not create) if `listen_addr` is a wildcard; otherwise defaults to the listener IP. A wildcard value is rejected — ICE needs the reply to come from the address the check was sent to. |
| `advertise_ip` | string | Substituted into XOR-RELAYED-ADDRESS for 1:1 NAT. Never used for XOR-MAPPED-ADDRESS. |
| `relay_min_port` / `relay_max_port` | int | Default `49152`–`51199` (narrower than the RFC span so a flood cannot eat the process's ephemeral ports). Inverted range ⇒ 400. Reserve it at the OS. |
| `max_lifetime_secs` | int | Ceiling on a granted allocation lifetime. `0`/omitted ⇒ 3600; floor 600. |
| `allow_private` | bool | RFC1918 / loopback / link-local peers. Default `false`. UNSAFE — see §7. |
| `max_datagram` | int | Relay read buffer. `0`/omitted ⇒ 2048; hard cap 65000. |
| `max_permissions` | int | `0`/omitted ⇒ 128. |
| `max_channels` | int | `0`/omitted ⇒ 64. |
| `max_allocations_per_user` | int | Per the **userid** half of the REST username, not the full `expiry:userid` string (the timestamp prefix rotates). `0`/omitted ⇒ 16. |
| `credential_horizon_secs` | int | Reject **Allocate** credentials whose embedded expiry is further out than this. `0`/omitted ⇒ 86400. Refresh / CreatePermission / ChannelBind do **not** re-check REST expiry (coturn / LiveKit 1.12); HMAC and userid still verified. |

There is **no minting endpoint**. Compute the REST credential locally from the
secret you just stored:

```
username = "<unix_expiry>:<userid>"   # both halves non-empty; first colon delimits
password = base64(HMAC-SHA1(static_secret, username))
```

```bash
python -c "import hmac,hashlib,base64,time
s='YOUR_SECRET'; u=f'{int(time.time())+3600}:alice'
print(u)
print(base64.b64encode(hmac.new(s.encode(), u.encode(), hashlib.sha1).digest()).decode())"
```

`max_connections` still applies, but as an allocation cap, clamped to the relay
port-range size. `0` (unlimited) is not honoured — every allocation binds a
socket, so the cap becomes the range capacity.

### `smtp` object

An `smtp` proxy is a thin **egress relay**: it accepts SMTP submission from a
trusted client MTA (typically your own mail server), resolves each recipient
domain's MX records and delivers from this host's own public IP. It keeps **no
queue** — the upstream MX reply is relayed back to the client verbatim, so the
client MTA's retry/bounce machinery still owns delivery. Recipients are grouped
by domain, one pooled upstream connection each; `DATA` is buffered (bounded by
`max_message_bytes`) and replayed per domain. History rows show the resolved
domains as `mx:example.com,…`.

| Field | Type | Semantics |
|---|---|---|
| `helo_name` | string | **Required.** EHLO identity sent to clients and upstream MXs. Must be the hostname whose PTR points back at this relay's public IP (FCrDNS) — an empty or wrong one is the difference between delivery and a 550. Hostname or `[IP]` literal, ≤253 chars. |
| `upstream_port` | int | Port MX hosts are dialed on. `0`/omitted ⇒ 25. |
| `require_starttls` | bool | `true` ⇒ an MX without STARTTLS fails the RCPT with a 4xx instead of receiving cleartext. Upstream certs are always verified against Mozilla roots (`webpki-roots`) when TLS runs. |
| `allow_private` | bool | Permit MX/A records resolving to loopback/RFC1918/reserved. Default `false`. UNSAFE on untrusted listeners — SSRF via attacker-controlled DNS. |
| `max_message_bytes` | int | Buffered DATA ceiling. `0`/omitted ⇒ 35 MiB; hard cap 256 MiB. |
| `dns_servers` | `string[]` | Explicit DNS resolver IPs for MX/A lookups. `[]`/omitted ⇒ system config, falling back to public DNS (Cloudflare+Google) when `/etc/resolv.conf` cannot be parsed — seen in the field on systemd-stub hosts. Entries that are not IPs ⇒ 400. |

The whole object is a full replace on update (no tri-state fields inside).
Client-side `STARTTLS` is offered only when `server_p12` (or the global
`tls_cert`) is configured; `AUTH` offers `LOGIN` + `PLAIN` whenever `auth` is
set, and an unauthenticated relay is only allowed on a private bind.

### Minimal bodies per protocol

```jsonc
// socks5 with auth
{"name":"socks-eu","protocol":"socks5","listen_addr":"0.0.0.0:1080",
 "auth":{"username":"alice","password":"secret"}}

// http proxy with a header override
{"name":"http-out","protocol":"http","listen_addr":"0.0.0.0:1081",
 "override_headers":[{"key":"X-Forwarded-For","value":"redacted"}]}

// https listener with its own keystore + client mTLS required
{"name":"https-in","protocol":"https","listen_addr":"0.0.0.0:1082",
 "server_p12":"<base64>","server_p12_password":"…",
 "server_truststore_p12":"<base64>","server_truststore_password":"…",
 "mtls_required":true}

// shadowsocks
{"name":"ss","protocol":"shadowsocks","listen_addr":"0.0.0.0:8388",
 "ss_method":"aes-256-gcm","ss_password":"…"}

// tcp forwarder, 30 s connect timeout, unlimited connections
{"name":"tcp-smtp","protocol":"tcp","listen_addr":"0.0.0.0:2525",
 "forward_to":"mail.example.com:25","connect_timeout_secs":30,
 "max_connections":0}

// websocket tunnel
{"name":"ws-tunnel","protocol":"websocket","listen_addr":"0.0.0.0:1084",
 "forward_to":"10.0.0.5:22"}

// udp forwarder
{"name":"dns","protocol":"udp","listen_addr":"0.0.0.0:5300",
 "forward_to":"8.8.8.8:53","idle_timeout_secs":60}

// turn relay — listen_addr is UDP/TCP; send a concrete relay_ip when that
// address is a wildcard, otherwise start() fails after create succeeded.
{"name":"turn-eu","protocol":"turn","listen_addr":"0.0.0.0:3478",
 "turn":{"transports":["udp","tcp"],"realm":"turn.example.com",
         "static_secret":"<≥16 bytes>","relay_ip":"203.0.113.10"},
 "max_connections":512}

// turn with turns: — needs its own listen address AND a publicly-trusted
// server_p12 whose SAN matches the hostname in the turns: URL.
{"name":"turn-tls","protocol":"turn","listen_addr":"0.0.0.0:3478",
 "server_p12":"<base64>","server_p12_password":"…",
 "turn":{"transports":["udp","tcp","tls"],"tls_listen":"0.0.0.0:5349",
         "realm":"turn.example.com","static_secret":"<≥16 bytes>",
         "relay_ip":"203.0.113.10"}}

// smtp egress relay on a private/tailnet bind (auth optional there), or on a
// public bind where auth is mandatory. helo_name = the host whose PTR points
// back at this machine's public IP.
{"name":"mx-egress","protocol":"smtp","listen_addr":"100.64.0.1:2525",
 "smtp":{"helo_name":"mail.example.com"}}
{"name":"mx-egress-pub","protocol":"smtp","listen_addr":"0.0.0.0:2525",
 "auth":{"username":"mta","password":"<secret>"},
 "smtp":{"helo_name":"mail.example.com","require_starttls":true}}
```

## 4. Create and start

```bash
ID=$(curl -s -b "$JAR" -X POST "$BASE/api/proxies" \
  -H 'content-type: application/json' \
  -d '{"name":"socks-eu","protocol":"socks5","listen_addr":"0.0.0.0:1080",
       "auth":{"username":"alice","password":"secret"}}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["id"])')

curl -s -b "$JAR" -X POST "$BASE/api/proxies/$ID/start"
```

Verify by re-listing rather than trusting the `200`: a start that fails answers
`400 {"error":"cannot bind 0.0.0.0:1080: …"}`, and a start that succeeds shows
`"running": true` in the next `GET /api/proxies`.

## 5. Update — the two traps

**Trap 1: omitted ⇒ reset.** `POST /api/proxies/{id}` deserializes a whole
`ProxyForm`; every absent field takes its serde default and is persisted. Send
`{"name":"x","listen_addr":"0.0.0.0:1080"}` to "just rename" and you have also
dropped `auth`, `forward_to`, `override_headers`, all timeouts, reset
`max_connections` to the 8888 default, flipped `udp_associate_enabled` back
to `true`, and replaced `turn` with empty-realm defaults (which then 400s if
`protocol` is `turn`). **Always send the complete intended state.**

**Trap 2: the snapshot has no secrets.** `GET /api/proxies` returns
`ProxySnapshot`, which carries `auth_enabled`/`auth_username` but no password,
`ss_method` but no `ss_password`, `has_client_p12`/`has_server_p12`/
`has_truststore` booleans instead of keystores, and `turn.has_turn_secret`
instead of `static_secret`. Rebuilding a form from a snapshot therefore
silently strips credentials. Either keep the desired state in your own config
file and always send it in full, or re-supply the secrets on every update.

PKCS#12 fields and `turn.static_secret` are tri-state on update. Everything
else inside `turn` is a full replace of the nested object — omitting
`allow_private` / `relay_ip` / port range / … resets them to defaults.

PKCS#12 (`client_p12` / `server_p12` / `server_truststore_p12`):

| Value sent | Effect |
|---|---|
| field omitted / `null` | **keep** the stored keystore and its password |
| `""` (empty string) | **clear** the keystore *and* its associated passwords |
| base64 string | **replace** it, and take the accompanying password fields |

`turn.static_secret` (resolved *before* validate, so an edit that does not
retype it stays valid):

| Value sent | Effect |
|---|---|
| field omitted / `null` | **keep** the stored secret |
| `""` (empty string) | **400** — a missing secret is an open relay, so it cannot be cleared |
| string ≥16 bytes | **replace** |

So the safe update recipe is: send every non-secret field explicitly (including
the full `turn` object), omit `client_p12` / `server_p12` /
`server_truststore_p12` / `turn.static_secret` when you are not changing them,
and re-send `auth` / `ss_password` from your own source of truth.

Updating a **running** proxy stops it, saves, then starts it again — every live
connection through it is dropped. Do it in a maintenance window, or check
`running` first and tell the user what will be interrupted.

## 6. Idempotent reconciliation

Because names and listen addresses are not unique, a "create if missing" agent
must match explicitly:

```
desired = [ …your proxy specs… ]
existing = GET /api/proxies
for spec in desired:
    match = first p in existing where p.name == spec.name      # pick one key and stick to it
    if match is None:
        cfg = POST /api/proxies      (full body)
        id  = cfg.id
    else:
        id = match.id
        POST /api/proxies/{id}       (full body — see §5)
    if spec.should_run and not running(id):  POST /api/proxies/{id}/start
    if not spec.should_run and running(id):  POST /api/proxies/{id}/stop
verify: GET /api/proxies → assert running/listen_addr/protocol per spec
```

Matching on `name` is usually right (it is what a human recognises); matching on
`listen_addr` is right when the port is the identity. Do not match on both with
OR — that creates ambiguous double-matches. Store the returned `id` if you can:
it is the only stable key.

Proxies with `enabled: true` are auto-started on the next server launch, so
`stop` is what you want for "disable permanently", not `delete` + recreate.

## 7. Unsafe options — warn, never silently disable

This project favours permissive defaults with a loud warning. Support every
option the user asks for, but say plainly what it costs:

- **`send_proxy_protocol: true`** — writes a PROXY v1 header as the *first
  bytes* upstream. A destination not configured to expect it from this proxy's
  address sees garbage and drops **every** connection. Enable only after the
  destination side is confirmed.
- **`udp_allow_private: true`** — lets SOCKS5 UDP reach RFC1918/loopback/link-local
  targets. That is an SSRF pivot into the internal network.
- **`turn.allow_private: true`** — same SSRF through the TURN relay: peers may
  reach loopback, RFC1918 and link-local. Leave it off; 403s on the far end's
  private ICE candidates are normal.
- **TURN `transports: ["udp"]` only** — Send indications and ChannelData carry
  no MESSAGE-INTEGRITY, so the 5-tuple is the only authenticator on the datapath.
  `turns:`/`tcp` is the transport that resists spoofing.
- **`smtp` without `auth` on a public bind** — refused outright (400): an open
  SMTP relay is abuse-bait. On a private bind it is allowed but logged as a
  warning — keep that bind private forever.
- **`smtp.allow_private: true`** — MX/A records may point at loopback/RFC1918 —
  SSRF via attacker-controlled DNS. Leave off on anything untrusted can reach.
- **`smtp.helo_name` that does not match PTR** — the single most common cause
  of remote 550s. The name must be forward-confirmed against this machine's
  *public* IP, not the listen address.
- **`turns:` without a publicly-trusted `server_p12`** — the listener falls back
  to the global self-signed cert. Browsers validate `turns:` against the OS trust
  store with no JS bypass, so every browser client is rejected. Start still
  succeeds; the failure is on the client.
- **TURN on `0.0.0.0`/`::` with no `relay_ip`** — create succeeds, start returns
  400. A wildcard relay bind lets the kernel pick a source per route and breaks
  ICE while a packet capture looks healthy.
- **`max_connections: 0`** — unlimited. Removes the accept-time backstop against
  connection floods; the default 8888 exists for that reason. On `turn` it is
  not unlimited: the allocation cap is clamped to the relay port-range size.
- **`mtls_required: false` on an `https` listener** — anyone who can reach the
  port can use the proxy unless `auth` is set.
- **No `auth` on socks5/http/https/websocket** — an open relay if the listen
  address is routable. `0.0.0.0:…` on a public host means the internet. TURN
  cannot be run without `static_secret` (≥16 bytes); that is the only auth path.
- **Admin exposed without `admin_user`/`admin_password`** — the API you are
  calling is unauthenticated. Flag it; do not quietly "fix" it by editing the
  config.
- **`admin_https=false` behind real TLS termination** — the session cookie is
  sent without `Secure`.

## 8. Monitoring and history

`GET /ws` (session cookie required) delivers a snapshot immediately, then a
fresh one every second:

```json
{"type":"snapshot","ts":1750000000000,
 "proxies":[{"id":"…","name":"socks-eu","protocol":"socks5",
   "listen_addr":"0.0.0.0:1080","running":true,"auth_enabled":true,
   "auth_username":"alice","total_connections":42,
   "bytes_sent":1234,"bytes_received":5678,
   "blocklist":["1.2.3.4"],
   "turn":{"transports":["udp","tcp"],"realm":"","has_turn_secret":false,
     "allow_private":false},
   "active_connections":[{"id":"…","src_addr":"1.2.3.4:51234",
     "dst_addr":"example.com:443","bytes_sent":1,"bytes_received":2,
     "started_at":1750000000000}]}]}
```

`turn` is always present on a snapshot (`TurnView`): same shape as the form
object except `static_secret` is reduced to `has_turn_secret`. Non-TURN
proxies still carry the default view (`has_turn_secret: false`, empty realm).

For a one-shot read, `GET /api/proxies` returns the same `ProxySnapshot` array —
prefer it over opening a websocket when you only need current state.

Closed connections live in RocksDB; page them:

```bash
curl -s -b "$JAR" "$BASE/api/proxies/$ID/history?offset=0&limit=50"
# {"records":[{"id","proxy_id","src_addr","dst_addr","bytes_sent",
#              "bytes_received","started_at","closed_at"}],
#  "offset":0,"limit":50,"has_more":true}
```

Loop while `has_more`, advancing `offset` by `limit`. Timestamps are Unix epoch
**milliseconds**; `closed_at` is `null` only for records still open.

Terminate one live connection with its snapshot `id`:
`POST /api/proxies/{id}/conns/{cid}/kill`.

## 9. Blocklists

Two independent layers, both persisted and both enforced at accept time:

- **Global** `/api/blocklist` — refuses the address on every proxy.
- **Per-proxy** `/api/proxies/{id}/blocklist` — refuses it on that proxy only.

Both accept a bare `IP` (matches any source port) or an exact `IP:port`, and
both drop matching live connections immediately on add. Removal takes the same
`{"addr":…}` body via `DELETE`.

On a `turn` proxy, permissions are keyed on **IP only** (RFC 8656). A block
of the form `1.2.3.4:25` cannot refuse the permission itself; it still applies
per datagram. Use a bare IP to refuse the permission.

```bash
curl -s -b "$JAR" -X POST "$BASE/api/blocklist" \
  -H 'content-type: application/json' -d '{"addr":"203.0.113.7"}'
```

Note the per-proxy list is *not* cleared by an update (it is not part of
`ProxyForm`), but it *is* destroyed along with the proxy on `DELETE`.

## 10. Error reference

| Response | Meaning | Do this |
|---|---|---|
| `401 {"error":"login required"}` | No/expired session (server restarted?) | Log in once, retry the call. |
| `429` + `Retry-After` | >10 failed logins from this IP in 60 s | Wait the header's seconds. Stop retrying the password. |
| `401 {"error":"invalid username or password"}` | Bad credentials | Ask the user. One more blind attempt costs part of the budget of 10. |
| `401 {"error":"login is not allowed from your network"}` | `admin_network` CIDR excludes you | Call from an allowed IP. |
| `400 {"error":"name is required"}` | Blank/whitespace name | |
| `400 {"error":"name must not contain control characters"}` | CR/LF/etc. in name | Strip them. |
| `400 {"error":"name is too long (max 200 characters)"}` | | |
| `400 {"error":"listen address is required"}` | | |
| `400 {"error":"this proxy needs a forward destination (host:port)"}` | `tcp`/`websocket`/`udp` without `forward_to` | Not raised for `turn`. |
| `400 {"error":"turn needs a realm: 1-127 printable ASCII characters, no space, quote or backslash (an empty realm makes browsers fail every allocation)"}` | Missing/illegal `turn.realm` | |
| `400 {"error":"turn needs a static_secret of at least 16 bytes — the REST API is the only auth path, so a short or empty secret is an open relay"}` | Missing/short secret on create, or `""` on update | Omit the field to keep the stored secret. |
| `400 {"error":"turn needs at least one transport (udp, tcp or tls)"}` | `turn.transports` empty | Default if omitted is `["udp","tcp"]` — this fires when you send `[]`. |
| `400 {"error":"unknown turn transport \"…\" (expected udp, tcp or tls)"}` | Typo in `transports` | |
| `400 {"error":"the turn tls transport needs its own listen address (turns: port)"}` | `tls` without `tls_listen` | |
| `400 {"error":"turn relay port range is inverted (X > Y)"}` | `relay_min_port` > `relay_max_port` | |
| `400 {"error":"turn needs a concrete relay_ip when the listener binds a wildcard address"}` | Start, not create. `listen_addr` is `0.0.0.0`/`::` and `relay_ip` is blank | Set a concrete `relay_ip`. |
| `400 {"error":"turn relay_ip must not be a wildcard address"}` | `relay_ip` is `0.0.0.0`/`::` | |
| `400 {"error":"cannot bind <addr> (turn/udp\|tcp\|tls): …"}` | Port taken on that TURN transport | UDP and TCP share `listen_addr`; TLS uses `tls_listen`. A failed start leaves the proxy stopped (no partial bind). |
| `400 {"error":"shadowsocks needs a cipher: …"}` | Bad/missing `ss_method` | Use one of the three ciphers. |
| `400 {"error":"shadowsocks needs a password"}` | | |
| `400 {"error":"proxy not found"}` | Wrong/stale `id` | Re-list. |
| `400 {"error":"cannot bind <addr>: …"}` | Port taken, address not local, or privileged port | Change port, free it, or run with rights for <1024. |
| `400 {"error":"the keystore is not valid base64"}` | Sent PEM, a `data:` URL, or wrapped base64 | Send trimmed standard base64 of the raw `.p12`. |
| `400 {"error":"cannot open PKCS#12 keystore (wrong password?): …"}` | Wrong `*_p12_password` or not a PKCS#12 | |
| `400 {"error":"connection not found (it may have already closed)"}` | Race with a closing connection | Benign; re-snapshot. |
| Non-JSON `4xx` (plain text) | Body failed to deserialize before the handler | Fix the JSON: missing `name`/`listen_addr`, wrong type, bad `protocol` value. |
| Connection refused | Server not running, or bound to another interface | `GET /api/session` on the right host:port; the server may be daemonised (`sn-proxy stop` kills it, `--mode foreground` keeps it attached). |

## 11. End-to-end PowerShell example

```powershell
$Base = 'http://127.0.0.1:8080'
$S = New-Object Microsoft.PowerShell.Commands.WebRequestSession

$sess = Invoke-RestMethod "$Base/api/session"
if ($sess.auth_required) {
  Invoke-RestMethod "$Base/api/login" -Method Post -WebSession $S `
    -ContentType 'application/json' `
    -Body (@{ username = 'admin'; password = $env:SNP_PASS } | ConvertTo-Json)
}

$spec = @{
  name         = 'socks-eu'
  protocol     = 'socks5'
  listen_addr  = '0.0.0.0:1080'
  auth         = @{ username = 'alice'; password = $env:SNP_PROXY_PASS }
  idle_timeout_secs = 300
  max_connections   = 2000
}

$existing = Invoke-RestMethod "$Base/api/proxies" -WebSession $S
$match = $existing | Where-Object { $_.name -eq $spec.name } | Select-Object -First 1

if ($null -eq $match) {
  $cfg = Invoke-RestMethod "$Base/api/proxies" -Method Post -WebSession $S `
           -ContentType 'application/json' -Body ($spec | ConvertTo-Json -Depth 5)
  $id = $cfg.id
} else {
  $id = $match.id
  Invoke-RestMethod "$Base/api/proxies/$id" -Method Post -WebSession $S `
    -ContentType 'application/json' -Body ($spec | ConvertTo-Json -Depth 5) | Out-Null
}

Invoke-RestMethod "$Base/api/proxies/$id/start" -Method Post -WebSession $S | Out-Null

# verify, and report state rather than assuming the 200 meant "listening"
Invoke-RestMethod "$Base/api/proxies" -WebSession $S |
  Where-Object { $_.id -eq $id } |
  Select-Object name, protocol, listen_addr, running, auth_enabled, max_connections
```

`ConvertTo-Json` defaults to depth 2 and would flatten `auth` /
`override_headers` / `turn` into type names — always pass `-Depth 5` or more.
