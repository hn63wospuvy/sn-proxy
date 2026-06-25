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

def test_domain_literal_reply(sport):
    # The relay resolves the domain via the OS and forwards to the FIRST
    # address returned. On some hosts (notably Windows) "localhost" resolves to
    # ::1 before 127.0.0.1, so the echo server must accept both families: bind a
    # dual-stack IPv6 socket (IPV6_V6ONLY=0). Skip if the host lacks IPv6.
    fams = {ai[0] for ai in socket.getaddrinfo("localhost", 0, type=socket.SOCK_DGRAM)}
    try:
        echo = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        echo.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        echo.bind(("::", 0))
        eport = echo.getsockname()[1]
    except OSError:
        # No IPv6 / dual-stack: fall back to an IPv4 echo server. Only valid if
        # localhost does not prefer IPv6.
        if socket.AF_INET6 in fams:
            print("SKIP test_domain_literal_reply (no dual-stack; localhost prefers IPv6)")
            return
        echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    name = b"localhost"
    pkt = b"\x00\x00\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", eport) + b"q"
    cli.sendto(pkt, (bnd_ip, bnd_port))
    echo.settimeout(2); data, src = echo.recvfrom(2048)
    echo.sendto(b"r", src)
    cli.settimeout(2); rep, _ = cli.recvfrom(2048)
    h = parse_reply(rep)
    assert h["atyp"] in (0x01, 0x04), "reply ATYP must be literal, never 0x03"
    assert h["data"] == b"r"
    ctrl.close(); echo.close(); cli.close()
    print("OK test_domain_literal_reply")

def api(admin, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{HOST}:{admin}{path}", data=data,
                                 method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    return urllib.request.urlopen(req)

def snapshot(admin):
    return json.loads(api(admin, "GET", "/api/proxies").read())

def test_lifetime_teardown(admin, pid, sport):
    echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.sendto(frame(0x01, socket.inet_aton(HOST), eport, b"a"), (bnd_ip, bnd_port))
    echo.settimeout(2); echo.recvfrom(2048)
    ctrl.close(); time.sleep(0.4)  # control conn closed → association ends
    cli.sendto(frame(0x01, socket.inet_aton(HOST), eport, b"b"), (bnd_ip, bnd_port))
    echo.settimeout(0.8)
    try:
        echo.recvfrom(2048); raise AssertionError("relay must stop after TCP close")
    except socket.timeout:
        pass
    echo.close(); cli.close()
    print("OK test_lifetime_teardown")

def test_blocklist_per_proxy(admin, pid, sport):
    # Two echo servers; block ONE destination via the per-proxy list, the other
    # stays open. On an all-loopback host the control connection and the
    # destination share the IP 127.0.0.1, so we block the DESTINATION's full
    # IP:port (127.0.0.1:<bport>). That neither refuses the control connection
    # (different source port) nor tears down the live association, but does drop
    # the datagram to the blocked dest. The open echo server still receives.
    blocked, bport = udp_echo_server()
    openes, oport = udp_echo_server()
    api(admin, "POST", f"/api/proxies/{pid}/blocklist", {"addr": f"127.0.0.1:{bport}"})
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.sendto(frame(0x01, socket.inet_aton(HOST), bport, b"x"), (bnd_ip, bnd_port))
    blocked.settimeout(0.8)
    try:
        blocked.recvfrom(2048); raise AssertionError("per-proxy blocked dest must drop")
    except socket.timeout:
        pass
    # Control plane intact: the non-blocked dest still receives.
    cli.sendto(frame(0x01, socket.inet_aton(HOST), oport, b"y"), (bnd_ip, bnd_port))
    openes.settimeout(2)
    data, _ = openes.recvfrom(2048)
    assert data == b"y", data
    api(admin, "DELETE", f"/api/proxies/{pid}/blocklist", {"addr": f"127.0.0.1:{bport}"})
    ctrl.close(); blocked.close(); openes.close(); cli.close()
    print("OK test_blocklist_per_proxy")

def test_ssrf_mapped(admin, pid, sport):
    # udp_allow_private MUST be false for this proxy.
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # ::ffff:127.0.0.1 mapped → must be dropped; we just assert no crash + no reply.
    mapped = socket.inet_pton(socket.AF_INET6, "::ffff:7f00:1")
    cli.sendto(frame(0x04, mapped, 9, b"x"), (bnd_ip, bnd_port))
    cli.settimeout(0.8)
    try:
        cli.recvfrom(2048); raise AssertionError("mapped-internal dest must drop")
    except socket.timeout:
        pass
    ctrl.close(); cli.close()
    print("OK test_ssrf_mapped")

def test_accounting(admin, pid, sport):
    echo, eport = udp_echo_server()
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.sendto(frame(0x01, socket.inet_aton(HOST), eport, b"12345"), (bnd_ip, bnd_port))
    echo.settimeout(2); data, src = echo.recvfrom(2048); echo.sendto(b"678", src)
    cli.settimeout(2); cli.recvfrom(2048); time.sleep(0.4)
    snap = [p for p in snapshot(admin) if p["id"] == pid][0]
    conns = snap["active_connections"]
    assert conns and conns[0]["bytes_sent"] == 5 and conns[0]["bytes_received"] == 3, conns
    ctrl.close(); echo.close(); cli.close()
    print("OK test_accounting")

def test_admin_terminate_ip(admin, pid, sport):
    ctrl = socket.create_connection((HOST, sport))
    socks_associate(ctrl)
    time.sleep(0.3)
    snap = [p for p in snapshot(admin) if p["id"] == pid][0]
    assert snap["active_connections"], "association must be live"
    api(admin, "POST", "/api/blocklist", {"addr": "127.0.0.1"})  # block bare IP
    time.sleep(0.4)
    snap = [p for p in snapshot(admin) if p["id"] == pid][0]
    assert not snap["active_connections"], "blocking peer IP must tear down"
    api(admin, "DELETE", "/api/blocklist", {"addr": "127.0.0.1"})
    ctrl.close()
    print("OK test_admin_terminate_ip")

def test_proxy_stop_teardown(admin, pid, sport):
    ctrl = socket.create_connection((HOST, sport))
    bnd_ip, bnd_port = socks_associate(ctrl)
    api(admin, "POST", f"/api/proxies/{pid}/stop")
    time.sleep(0.4)
    snap = [p for p in snapshot(admin) if p["id"] == pid][0]
    assert not snap["running"] and not snap["active_connections"]
    api(admin, "POST", f"/api/proxies/{pid}/start"); time.sleep(0.3)
    ctrl.close()
    print("OK test_proxy_stop_teardown")

def test_feature_gate(admin):
    # Separate proxy with udp_associate_enabled=false.
    cfg = json.loads(api(admin, "POST", "/api/proxies", {
        "name": "noudp", "protocol": "socks5", "listen_addr": f"{HOST}:11081",
        "udp_associate_enabled": False,
    }).read())
    api(admin, "POST", f"/api/proxies/{cfg['id']}/start"); time.sleep(0.3)
    ctrl = socket.create_connection((HOST, 11081))
    ctrl.sendall(b"\x05\x01\x00"); assert ctrl.recv(2) == b"\x05\x00"
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = ctrl.recv(4)
    assert rep[1] == 0x07, f"disabled UDP must reply 0x07, got {rep!r}"
    ctrl.close()
    print("OK test_feature_gate")

def test_ipv6_roundtrip(admin):
    try:
        t = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); t.bind(("::1", 0)); t.close()
    except OSError:
        print("SKIP test_ipv6_roundtrip (no ::1)"); return
    cfg = json.loads(api(admin, "POST", "/api/proxies", {
        "name": "v6", "protocol": "socks5", "listen_addr": "[::1]:11082",
        "udp_associate_enabled": True, "udp_allow_private": True,
    }).read())
    api(admin, "POST", f"/api/proxies/{cfg['id']}/start"); time.sleep(0.3)
    echo = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); echo.bind(("::1", 0))
    eport = echo.getsockname()[1]
    ctrl = socket.create_connection(("::1", 11082))
    bnd_ip, bnd_port = socks_associate(ctrl)
    cli = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    addr6 = socket.inet_pton(socket.AF_INET6, "::1")
    cli.sendto(frame(0x04, addr6, eport, b"v6ping"), (bnd_ip, bnd_port))
    echo.settimeout(2); data, src = echo.recvfrom(2048); echo.sendto(b"v6pong", src)
    cli.settimeout(2); rep, _ = cli.recvfrom(2048)
    h = parse_reply(rep)
    assert h["atyp"] == 0x04 and h["data"] == b"v6pong", h
    ctrl.close(); echo.close(); cli.close()
    print("OK test_ipv6_roundtrip")

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

def create_proxy(admin, name, listen_addr, allow_private=False, enabled=True, start=True):
    cfg = json.loads(api(admin, "POST", "/api/proxies", {
        "name": name, "protocol": "socks5", "listen_addr": listen_addr,
        "udp_associate_enabled": enabled, "udp_allow_private": allow_private,
    }).read())
    pid = cfg["id"]
    if start:
        api(admin, "POST", f"/api/proxies/{pid}/start"); time.sleep(0.3)
    return pid

if __name__ == "__main__":
    # The relay proxy uses loopback echo servers, so allow_private=True is
    # required for the forward path to reach them. boot_and_create makes the
    # main relay proxy on 11080 (allow_private=True).
    proc, admin, pid, sport = boot_and_create(allow_private=True)
    failures = []
    def run(fn, *args):
        try:
            fn(*args)
        except Exception as e:
            failures.append((fn.__name__, repr(e)))
            print(f"FAIL {fn.__name__}: {e!r}")
    try:
        # Core relay tests against the allow_private=True proxy.
        run(test_handshake_and_bnd, sport)
        run(test_frag_dropped, sport)
        run(test_reflection_guard, sport)
        run(test_echo_roundtrip, sport)
        run(test_domain_literal_reply, sport)
        run(test_lifetime_teardown, admin, pid, sport)
        run(test_accounting, admin, pid, sport)
        run(test_blocklist_per_proxy, admin, pid, sport)
        run(test_proxy_stop_teardown, admin, pid, sport)
        run(test_admin_terminate_ip, admin, pid, sport)
        # SSRF test needs allow_private=FALSE → its own proxy on 11083.
        ssrf_pid = create_proxy(admin, "ssrf", f"{HOST}:11083", allow_private=False)
        run(test_ssrf_mapped, admin, ssrf_pid, 11083)
        # Feature gate + IPv6 create their own proxies internally.
        run(test_feature_gate, admin)
        run(test_ipv6_roundtrip, admin)
    finally:
        shutdown(proc)
    if failures:
        print(f"\n{len(failures)} FAILURE(S): " + ", ".join(n for n, _ in failures))
        sys.exit(1)
    print("\nALL TESTS PASSED")
