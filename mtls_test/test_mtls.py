"""End-to-end mTLS test for sn-proxy.

Assumes the following are already running:
  * sn-proxy            web admin API at http://127.0.0.1:8088
  * mtls_server.py      mTLS destination at https://127.0.0.1:9444

It then:
  1. creates three proxies through the admin API:
       - mtls-client : http  proxy with a PKCS#12 client identity
       - noclient    : http  proxy with no client identity
       - mtls-listener: https proxy whose listener requires client certs
  2. CLIENT mTLS  — forwards an `https://` request through `mtls-client`;
     the destination must report the proxy's client certificate. The same
     request through `noclient` must fail (no certificate presented).
  3. SERVER mTLS — connects to the `mtls-listener` HTTPS proxy: with a client
     certificate the proxied request succeeds; without one the TLS handshake
     is refused.

Exits non-zero if any check fails.
"""

import base64
import json
import socket
import ssl
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
API = "http://127.0.0.1:8088"
DEST = ("127.0.0.1", 9444)        # mtls_server.py
PLAIN = ("127.0.0.1", 9446)      # local plain-HTTP target started below
results = []


def check(name, ok, detail=""):
    results.append(ok)
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)


# --------------------------------------------------------------------------
# A plain HTTP target so the HTTPS-listener test stays fully local.
# --------------------------------------------------------------------------
class PlainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"plain-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_plain_server():
    srv = HTTPServer(PLAIN, PlainHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------
# Admin API helpers
# --------------------------------------------------------------------------
def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


def wait_for_api():
    for _ in range(50):
        try:
            api("GET", "/api/proxies")
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit("sn-proxy admin API never came up on " + API)


def b64(name):
    return base64.b64encode((HERE / name).read_bytes()).decode()


def create_proxy(spec):
    try:
        status, body = api("POST", "/api/proxies", spec)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"create {spec['name']} failed: {e.read().decode()}")
    pid = body["id"]
    try:
        api("POST", f"/api/proxies/{pid}/start")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"start {spec['name']} failed: {e.read().decode()}")
    return pid


# --------------------------------------------------------------------------
# CLIENT mTLS — send an absolute-form `https://` request through an http proxy
# --------------------------------------------------------------------------
def http_proxy_get_https(proxy_addr, target):
    """Send `GET <target> HTTP/1.1` (absolute form) to a plain HTTP proxy."""
    with socket.create_connection(proxy_addr, timeout=10) as s:
        host = target.split("://", 1)[1].split("/", 1)[0]
        req = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req.encode())
        chunks = []
        s.settimeout(10)
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)


# --------------------------------------------------------------------------
# SERVER mTLS — talk to the HTTPS proxy listener, with/without a client cert
# --------------------------------------------------------------------------
def https_proxy_get(with_client_cert):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(HERE / "ca.crt"))
    if with_client_cert:
        ctx.load_cert_chain(HERE / "client.crt", HERE / "client.key")
    raw = socket.create_connection(("127.0.0.1", 9445), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    try:
        target = f"http://{PLAIN[0]}:{PLAIN[1]}/"
        req = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {PLAIN[0]}:{PLAIN[1]}\r\n"
            f"Connection: close\r\n\r\n"
        )
        tls.sendall(req.encode())
        chunks = []
        tls.settimeout(10)
        while True:
            try:
                d = tls.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)
    finally:
        tls.close()


def main():
    start_plain_server()
    wait_for_api()

    print("Creating proxies via the admin API...", flush=True)
    create_proxy({
        "name": "mtls-client",
        "protocol": "http",
        "listen_addr": "127.0.0.1:8082",
        "client_p12": b64("client.p12"),
        "client_p12_password": "testpass",
    })
    create_proxy({
        "name": "noclient",
        "protocol": "http",
        "listen_addr": "127.0.0.1:8083",
    })
    create_proxy({
        "name": "mtls-listener",
        "protocol": "https",
        "listen_addr": "127.0.0.1:9445",
        "server_p12": b64("server.p12"),
        "server_p12_password": "testpass",
        "server_truststore_p12": b64("truststore.p12"),
        "server_truststore_password": "testpass",
        "mtls_required": True,
    })
    time.sleep(1.0)  # let the listeners bind

    print("\nCLIENT mTLS (proxy presents a client certificate upstream):", flush=True)
    resp = http_proxy_get_https(("127.0.0.1", 8082), "https://127.0.0.1:9444/")
    head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    check(
        "request via mtls-client reaches the mTLS destination",
        b"mtls-ok" in resp,
        head,
    )
    check(
        "destination saw the proxy's client certificate",
        b"client=sn-proxy test client" in resp,
        resp.split(b"\r\n\r\n", 1)[-1].strip().decode(errors="replace"),
    )

    resp = http_proxy_get_https(("127.0.0.1", 8083), "https://127.0.0.1:9444/")
    head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    check(
        "request via noclient is rejected by the mTLS destination",
        b"mtls-ok" not in resp,
        head or "<connection closed with no response>",
    )

    print("\nSERVER mTLS (HTTPS listener requires a client certificate):", flush=True)
    resp = https_proxy_get(with_client_cert=True)
    head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    check(
        "client WITH a certificate is accepted and proxied",
        b"plain-ok" in resp,
        head,
    )

    try:
        https_proxy_get(with_client_cert=False)
        check("client WITHOUT a certificate is refused", False, "handshake unexpectedly succeeded")
    except (ssl.SSLError, ConnectionResetError, OSError) as e:
        check("client WITHOUT a certificate is refused", True, type(e).__name__)

    print()
    if all(results):
        print(f"ALL {len(results)} CHECKS PASSED")
        sys.exit(0)
    print(f"{results.count(False)} of {len(results)} CHECKS FAILED")
    sys.exit(1)


if __name__ == "__main__":
    main()
