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

def udp_echo_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    return s, s.getsockname()[1]

def frame(atyp, addrbytes, port, data):
    return b"\x00\x00\x00" + bytes([atyp]) + addrbytes + struct.pack("!H", port) + data

def parse_reply(rep):
    assert rep[0:3] == b"\x00\x00\x00"
    atyp = rep[3]
    if atyp == 0x01:
        ip = socket.inet_ntoa(rep[4:8]); off = 8
    elif atyp == 0x04:
        ip = socket.inet_ntop(socket.AF_INET6, rep[4:20]); off = 20
    else:
        raise AssertionError("reply must be literal")
    port = struct.unpack("!H", rep[off:off+2])[0]
    return {"atyp": atyp, "ip": ip, "port": port, "data": rep[off+2:]}

def test_echo_roundtrip(sport):
    echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = frame(0x01, socket.inet_aton(HOST), eport, b"ping")
    cli.sendto(pkt, (bnd_ip, bnd_port))
    echo.settimeout(2); data, src = echo.recvfrom(2048)
    assert data == b"ping", data
    echo.sendto(b"pong", src)
    cli.settimeout(2); rep, _ = cli.recvfrom(2048)
    h = parse_reply(rep)
    assert h["data"] == b"pong" and h["atyp"] == 0x01
    ctrl.close(); echo.close(); cli.close()
    print("OK test_echo_roundtrip")

def test_frag_dropped(sport):
    echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = b"\x00\x00\x01\x01" + socket.inet_aton(HOST) + struct.pack("!H", eport) + b"x"
    cli.sendto(pkt, (bnd_ip, bnd_port))
    echo.settimeout(0.8)
    try:
        echo.recvfrom(2048); raise AssertionError("FRAG!=0 must be dropped")
    except socket.timeout:
        pass
    ctrl.close(); echo.close(); cli.close()
    print("OK test_frag_dropped")

def test_reflection_guard(sport):
    echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    # send from a fresh socket that has NOT been pinned via the first datagram —
    # source IP equals control peer IP (127.0.0.1) here, so to truly test the
    # cross-source drop we rely on the pin: send a first datagram to pin, then
    # from a DIFFERENT port (a different 2-tuple) — must be dropped.
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.sendto(frame(0x01, socket.inet_aton(HOST), eport, b"a"), (bnd_ip, bnd_port))
    echo.settimeout(2); echo.recvfrom(2048)  # pin established
    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other.sendto(frame(0x01, socket.inet_aton(HOST), eport, b"b"), (bnd_ip, bnd_port))
    echo.settimeout(0.8)
    try:
        echo.recvfrom(2048); raise AssertionError("unpinned source must be dropped")
    except socket.timeout:
        pass
    ctrl.close(); echo.close(); cli.close(); other.close()
    print("OK test_reflection_guard")

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
    # The relay proxy uses loopback echo servers, so allow_private=True is
    # required for the forward path to reach them.
    proc, admin, pid, sport = boot_and_create(allow_private=True)
    try:
        test_handshake_and_bnd(sport)
        test_frag_dropped(sport)
        test_reflection_guard(sport)
        test_echo_roundtrip(sport)
    finally:
        shutdown(proc)
