---
name: sn-proxy-admin-api
description: Use when an agent must create, update, start/stop, block, inspect or reconcile sn-proxy proxy instances over the HTTP admin API (`/api/proxies`, `/api/blocklist`, `/ws`) instead of clicking the web admin — covers login/session, the full ProxyForm field reference, per-protocol required fields, the full-replace update trap, and error recovery.
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
   omit reverts to its default — except the four PKCS#12 groups, which are
   tri-state. See §5.
3. **`GET /api/proxies` never returns secrets.** No proxy password, no
   Shadowsocks password, no keystore password. A blind read-modify-write wipes
   them. Keep your own desired-state, or re-send the secrets. See §5.
4. **Create leaves the proxy stopped.** A new proxy has `enabled: false` and is
   not listening until you `POST /api/proxies/{id}/start`.
5. **Nothing is unique.** Two proxies may share a name *and* a listen address;
   the collision only surfaces as a bind error at start. Reconcile by listing
   first (§6) or you will create duplicates on every run.
6. **Never print secrets.** `POST /api/proxies` echoes back the full
   `ProxyConfig` *including* passwords and base64 keystores. Do not log the
   response body verbatim.

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
| `protocol` | enum | all | `socks5`\|`http`\|`https`\|`shadowsocks`\|`tcp`\|`websocket`\|`udp`. Omitted ⇒ `socks5`. |
| `listen_addr` | string | all | Required, e.g. `0.0.0.0:1080`. Not validated until start. |
| `auth` | `{username,password}` | socks5, http, https, websocket | Omitted, or `username` exactly `""` ⇒ no auth. |
| `ss_method` | string | shadowsocks | Required: `aes-128-gcm`, `aes-256-gcm` or `chacha20-ietf-poly1305`. |
| `ss_password` | string | shadowsocks | Required, non-empty. |
| `forward_to` | `host:port` | tcp, websocket, udp | **Required for these three.** Ignored elsewhere. |
| `keepalive_secs` | int | all | `0`/omitted ⇒ off. |
| `idle_timeout_secs` | int | all | `0`/omitted ⇒ off (udp applies its own 60 s default). |
| `connect_timeout_secs` | int | all | `0`/omitted ⇒ off. |
| `max_connections` | int | all | Omitted/`null` ⇒ **8888**; `0` ⇒ **unlimited**; `n` ⇒ `n`. Passed through verbatim — `0` is not coerced. |
| `send_proxy_protocol` | bool | tcp | PROXY protocol v1 header. Default `false`. See §7. |
| `override_headers` | `[{key,value}]` | http, https | Injected on plain-forwarded HTTP. Blank `key` entries are dropped. |
| `client_p12` | base64 | http, https | Client mTLS identity toward the destination. |
| `client_p12_password` | string | http, https | |
| `client_p12_alias` | string | http, https | Keystore entry; empty ⇒ first private key. |
| `client_p12_entry_password` | string | http, https | Rarely needed. |
| `server_p12` | base64 | https | Listener keystore; absent ⇒ the global `tls_cert`/`tls_key` or a self-signed cert. |
| `server_p12_password` | string | https | |
| `server_truststore_p12` | base64 | https | CA set validating client certs. |
| `server_truststore_password` | string | https | |
| `mtls_required` | bool | https | Require a client certificate. Default `false`. |
| `udp_associate_enabled` | bool | socks5 | **Omitted ⇒ `true`.** `false` makes the server reply `0x07` to `CMD=0x03`. |
| `udp_allow_private` | bool | socks5 | Allows RFC1918/internal UDP destinations. **SSRF risk** — see §7. |
| `udp_bind_addr` | string | socks5 | Relay socket bind; default = listener IP. |
| `udp_advertise_ip` | string | socks5 | IP reported in `BND.ADDR` (NAT / multi-homed). |
| `udp_max_datagram` | int | socks5 | Default 64 KiB. `0` ⇒ default. |
| `udp_max_dests` | int | socks5 | `0`/omitted ⇒ unlimited. |

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
{"name":"smtp-relay","protocol":"tcp","listen_addr":"0.0.0.0:2525",
 "forward_to":"mail.example.com:25","connect_timeout_secs":30,
 "max_connections":0}

// websocket tunnel
{"name":"ws-tunnel","protocol":"websocket","listen_addr":"0.0.0.0:1084",
 "forward_to":"10.0.0.5:22"}

// udp forwarder
{"name":"dns","protocol":"udp","listen_addr":"0.0.0.0:5300",
 "forward_to":"8.8.8.8:53","idle_timeout_secs":60}
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
`max_connections` to the 8888 default and flipped `udp_associate_enabled` back
to `true`. **Always send the complete intended state.**

**Trap 2: the snapshot has no secrets.** `GET /api/proxies` returns
`ProxySnapshot`, which carries `auth_enabled`/`auth_username` but no password,
`ss_method` but no `ss_password`, and `has_client_p12`/`has_server_p12`/
`has_truststore` booleans instead of keystores. Rebuilding a form from a
snapshot therefore silently strips credentials. Either keep the desired state in
your own config file and always send it in full, or re-supply the secrets on
every update.

The PKCS#12 fields are the one exception — they are tri-state on update:

| Value sent | Effect |
|---|---|
| field omitted / `null` | **keep** the stored keystore and its password |
| `""` (empty string) | **clear** the keystore *and* its associated passwords |
| base64 string | **replace** it, and take the accompanying password fields |

So the safe update recipe is: send every non-secret field explicitly, omit
`client_p12` / `server_p12` / `server_truststore_p12` when you are not changing
them, and re-send `auth` / `ss_password` from your own source of truth.

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
- **`max_connections: 0`** — unlimited. Removes the accept-time backstop against
  connection floods; the default 8888 exists for that reason.
- **`mtls_required: false` on an `https` listener** — anyone who can reach the
  port can use the proxy unless `auth` is set.
- **No `auth` on socks5/http/https/websocket** — an open relay if the listen
  address is routable. `0.0.0.0:…` on a public host means the internet.
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
   "active_connections":[{"id":"…","src_addr":"1.2.3.4:51234",
     "dst_addr":"example.com:443","bytes_sent":1,"bytes_received":2,
     "started_at":1750000000000}]}]}
```

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
| `400 {"error":"this proxy needs a forward destination (host:port)"}` | `tcp`/`websocket`/`udp` without `forward_to` | |
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
`override_headers` into type names — always pass `-Depth 5` or more.
