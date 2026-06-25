import socket, struct, subprocess, sys, time, json, urllib.request, tempfile, os, signal

HOST = "127.0.0.1"

def socks_associate(ctrl, atyp=0x01, addr=b"\x00\x00\x00\x00", port=0):
    # method negotiation: no-auth
    ctrl.sendall(b"\x05\x01\x00")
    assert ctrl.recv(2) == b"\x05\x00", "no-auth not selected"
    # request: VER CMD=3 RSV ATYP DST.ADDR DST.PORT
    req = b"\x05\x03\x00" + bytes([atyp]) + addr + struct.pack("!H", port)
    ctrl.sendall(req)
    rep = ctrl.recv(4)
    assert rep[0] == 0x05 and rep[1] == 0x00, f"bad reply {rep!r}"
    atyp_r = rep[3]
    if atyp_r == 0x01:
        bnd_ip = socket.inet_ntoa(ctrl.recv(4))
    elif atyp_r == 0x04:
        bnd_ip = socket.inet_ntop(socket.AF_INET6, ctrl.recv(16))
    else:
        raise AssertionError("reply ATYP must be literal")
    bnd_port = struct.unpack("!H", ctrl.recv(2))[0]
    return bnd_ip, bnd_port

def test_handshake_and_bnd(port):
    ctrl = socket.create_connection((HOST, port))
    bnd_ip, bnd_port = socks_associate(ctrl)
    assert bnd_port != 0, "BND.PORT must be nonzero"
    assert bnd_ip not in ("0.0.0.0", "::"), f"BND.ADDR must be reachable, got {bnd_ip}"
    ctrl.close()
    print("OK test_handshake_and_bnd")

def boot_and_create(udp_enabled=True, allow_private=False):
    data = tempfile.mkdtemp(prefix="snudp-")
    admin_port = 18080
    proc = subprocess.Popen(
        [BIN, "-p", str(admin_port), "-d", data],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://{HOST}:{admin_port}/api/session", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)
    body = json.dumps({
        "name": "udp", "protocol": "socks5", "listen_addr": f"{HOST}:11080",
        "udp_associate_enabled": udp_enabled, "udp_allow_private": allow_private,
    }).encode()
    req = urllib.request.Request(f"http://{HOST}:{admin_port}/api/proxies",
                                 data=body, headers={"Content-Type": "application/json"})
    cfg = json.loads(urllib.request.urlopen(req).read())
    pid = cfg["id"]
    urllib.request.urlopen(urllib.request.Request(
        f"http://{HOST}:{admin_port}/api/proxies/{pid}/start", method="POST"))
    time.sleep(0.3)
    return proc, admin_port, pid, 11080

def _default_bin():
    # Resolve relative to the repo root (parent of this tests/ dir) so the
    # script works regardless of the caller's CWD.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "target", "debug", "sn-proxy")

BIN = os.environ.get("SN_PROXY_BIN") or _default_bin()
if sys.platform == "win32" and not BIN.endswith(".exe"):
    BIN += ".exe"

def shutdown(proc):
    # signal.SIGINT is not deliverable to a plain Popen on Windows; terminate()
    # maps to TerminateProcess there and SIGTERM elsewhere.
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)

if __name__ == "__main__":
    proc, admin, pid, sport = boot_and_create()
    try:
        test_handshake_and_bnd(sport)
    finally:
        shutdown(proc)
