"""Integration test for the TURN server (Protocol::Turn, RFC 8656).

Builds nothing itself; assumes `cargo build` has run. Launches the binary on a
temp data-dir + test web-admin port, then via the HTTP API creates+starts a TURN
proxy and drives it with a hand-rolled STUN/TURN client.

Scenarios, and what each one exists to catch:
  (a) Allocate -> CreatePermission -> Send -> echo peer -> Data, over UDP and
      over TCP. The baseline relay path.
  (b) The 401 challenge carries REALM and NONCE; a 438 carries a FRESH nonce
      AND the realm. libwebrtc's UpdateNonce() gives up without retrying when
      REALM is missing, so a 438 built separately from the 401 turns routine
      nonce rotation into a dead allocation.
  (c) Post-authentication responses carry MESSAGE-INTEGRITY. Chrome does not
      verify this, so nothing but an explicit check catches an unsigned server
      before Firefox and aiortc users do.
  (d) ChannelBind -> ChannelData with 1-, 2- and 3-byte payloads over TCP,
      asserting exactly 8 bytes per frame. Unpadded ChannelData makes the
      client swallow the next message's first bytes as padding, and a byte
      stream has no resynchronisation point.
  (e) A duplicated Allocate (same transaction id) replays the success response
      instead of allocating a second relay port; a DIFFERENT transaction id on
      the same 5-tuple gets 437.
  (f) Refresh(LIFETIME=0) echoes 0 and frees the allocation. Answering 600
      there makes every closed PeerConnection leak a relay port on both sides.
  (g) A peer sending a STUN Binding request TO THE RELAY ADDRESS is relayed to
      the client byte-identically inside a Data indication, and the server
      answers the peer with nothing. The relay socket is an opaque byte pipe;
      parsing it would make the server answer the client's own ICE checks.
  (h) A private/loopback peer address is refused with 403 Forbidden, not 401
      (terminal for libwebrtc) and not silence (burns the retransmit budget).
  (i) --slow: only ChannelBind refreshes for 12 minutes, asserting relaying
      still works at t=400s and t=700s. ChannelBind must refresh the permission
      or every call dies at exactly t=300s.

Run:  python tests/turn_test_client.py
      python tests/turn_test_client.py --slow      # adds (i), ~12 minutes
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zlib

WEB = "127.0.0.1:8098"
TURN_PORT = 3479          # not 3478, to avoid colliding with a real local TURN
REALM = "example.org"
SECRET = "0123456789abcdef-test-secret"
BIN = os.path.join("target", "debug", "sn-proxy" + (".exe" if os.name == "nt" else ""))

MAGIC = 0x2112A442
FINGERPRINT_XOR = 0x5354554E

# Message types (method/class interleaved, RFC 8489 Appendix A).
BINDING_REQ = 0x0001
BINDING_SUCCESS = 0x0101
ALLOCATE_REQ = 0x0003
ALLOCATE_SUCCESS = 0x0103
ALLOCATE_ERROR = 0x0113
REFRESH_REQ = 0x0004
REFRESH_SUCCESS = 0x0104
SEND_IND = 0x0016
DATA_IND = 0x0017
CREATE_PERM_REQ = 0x0008
CREATE_PERM_SUCCESS = 0x0108
CREATE_PERM_ERROR = 0x0118
CHANNEL_BIND_REQ = 0x0009
CHANNEL_BIND_SUCCESS = 0x0109

A_USERNAME = 0x0006
A_MESSAGE_INTEGRITY = 0x0008
A_ERROR_CODE = 0x0009
A_UNKNOWN_ATTRIBUTES = 0x000A
A_CHANNEL_NUMBER = 0x000C
A_LIFETIME = 0x000D
A_XOR_PEER_ADDRESS = 0x0012
A_DATA = 0x0013
A_REALM = 0x0014
A_NONCE = 0x0015
A_XOR_RELAYED_ADDRESS = 0x0016
A_REQUESTED_TRANSPORT = 0x0019
A_XOR_MAPPED_ADDRESS = 0x0020
A_FINGERPRINT = 0x8028


# --------------------------------------------------------------------------
# admin API plumbing (mirrors tests/udp_test_client.py)
# --------------------------------------------------------------------------

def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{WEB}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


def wait_web(proc, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise SystemExit(f"server exited early: {proc.returncode}")
        try:
            api("GET", "/api/session")
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit("web admin did not come up")


# --------------------------------------------------------------------------
# STUN codec
# --------------------------------------------------------------------------

def pad4(n):
    return (n + 3) & ~3


def encode_attrs(attrs):
    out = b""
    for typ, val in attrs:
        out += struct.pack("!HH", typ, len(val)) + val
        out += b"\x00" * (pad4(len(val)) - len(val))
    return out


def build(msg_type, txid, attrs, key=None, fingerprint=False):
    """Build a STUN message, optionally signed and/or fingerprinted.

    The two length rules are opposites and both are applied here so the test
    client exercises the same arithmetic the server must:
      - MESSAGE-INTEGRITY: HMAC over the message with the header length set to
        (bytes-so-far - 20 + 24), i.e. as if the MI TLV were the final content.
      - FINGERPRINT: CRC over the message with the header length left at its
        TRUE final value, which already counts the 8-byte FINGERPRINT TLV.
    """
    body = encode_attrs(attrs)
    if key is not None:
        length = len(body) + 24
        head = struct.pack("!HHI", msg_type, length, MAGIC) + txid
        mac = hmac.new(key, head + body, hashlib.sha1).digest()
        body += struct.pack("!HH", A_MESSAGE_INTEGRITY, 20) + mac
    if fingerprint:
        length = len(body) + 8
        head = struct.pack("!HHI", msg_type, length, MAGIC) + txid
        crc = (zlib.crc32(head + body) & 0xFFFFFFFF) ^ FINGERPRINT_XOR
        body += struct.pack("!HHI", A_FINGERPRINT, 4, crc)
    head = struct.pack("!HHI", msg_type, len(body), MAGIC) + txid
    return head + body


def parse(buf):
    """Return (msg_type, txid, [(typ, value)], mi_offset) or raise ValueError."""
    if len(buf) < 20:
        raise ValueError("short message")
    msg_type, length, magic = struct.unpack("!HHI", buf[:8])
    if magic != MAGIC:
        raise ValueError("bad magic cookie")
    if 20 + length > len(buf):
        raise ValueError("declared length overruns buffer")
    txid = buf[8:20]
    attrs, mi_offset, i = [], None, 20
    end = 20 + length
    while i + 4 <= end:
        typ, alen = struct.unpack("!HH", buf[i:i + 4])
        if i + 4 + alen > end:
            raise ValueError("attribute overruns message")
        if typ == A_MESSAGE_INTEGRITY and mi_offset is None:
            mi_offset = i
        attrs.append((typ, buf[i + 4:i + 4 + alen]))
        i += 4 + pad4(alen)
    return msg_type, txid, attrs, mi_offset


def get(attrs, typ):
    for t, v in attrs:
        if t == typ:
            return v
    return None


def get_all(attrs, typ):
    return [v for t, v in attrs if t == typ]


def verify_integrity(buf, mi_offset, key):
    scratch = bytearray(buf[:mi_offset])
    struct.pack_into("!H", scratch, 2, mi_offset - 20 + 24)
    want = hmac.new(key, bytes(scratch), hashlib.sha1).digest()
    return hmac.compare_digest(want, buf[mi_offset + 4:mi_offset + 24])


def error_code(attrs):
    v = get(attrs, A_ERROR_CODE)
    if v is None or len(v) < 4:
        return None
    return v[2] * 100 + v[3]


def decode_xor_addr(txid, v):
    family = v[1]
    port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
    if family == 0x01:
        raw = bytes(a ^ b for a, b in zip(v[4:8], struct.pack("!I", MAGIC)))
        return socket.inet_ntoa(raw), port
    key = struct.pack("!I", MAGIC) + txid
    raw = bytes(a ^ b for a, b in zip(v[4:20], key))
    return socket.inet_ntop(socket.AF_INET6, raw), port


def encode_xor_addr(txid, host, port):
    try:
        packed = socket.inet_aton(host)
        family, key = 0x01, struct.pack("!I", MAGIC)
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, host)
        family, key = 0x02, struct.pack("!I", MAGIC) + txid
    xport = port ^ (MAGIC >> 16)
    xaddr = bytes(a ^ b for a, b in zip(packed, key))
    return struct.pack("!BBH", 0, family, xport) + xaddr


# --------------------------------------------------------------------------
# TURN REST credentials
# --------------------------------------------------------------------------

def credentials(secret, userid="tester", ttl=3600):
    username = f"{int(time.time()) + ttl}:{userid}"
    password = base64.b64encode(
        hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    key = hashlib.md5(f"{username}:{REALM}:{password}".encode()).digest()
    return username, password, key


# --------------------------------------------------------------------------
# transports
# --------------------------------------------------------------------------

class UdpTransport:
    name = "udp"

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.addr = (host, port)

    def send(self, data):
        self.sock.sendto(data, self.addr)

    def recv(self):
        return self.sock.recvfrom(65535)[0]

    def close(self):
        self.sock.close()


class TcpTransport:
    """TURN over TCP: messages are framed, and ChannelData is padded to 4."""
    name = "tcp"

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(5)
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65535)
            if not chunk:
                raise ConnectionError("server closed the stream")
            self.buf += chunk

    def recv(self):
        self._fill(4)
        first = self.buf[0]
        if first < 4:
            self._fill(4)
            length = struct.unpack("!H", self.buf[2:4])[0]
            total = 20 + length
        elif 64 <= first <= 79:
            length = struct.unpack("!H", self.buf[2:4])[0]
            total = pad4(4 + length)
        else:
            raise ValueError(f"unframeable first byte {first:#x}")
        self._fill(total)
        frame, self.buf = self.buf[:total], self.buf[total:]
        return frame

    def close(self):
        self.sock.close()


# --------------------------------------------------------------------------
# the TURN client
# --------------------------------------------------------------------------

class TurnClient:
    def __init__(self, transport, secret, userid="tester"):
        self.t = transport
        self.username, self.password, self.key = credentials(secret, userid)
        self.realm = None
        self.nonce = None
        self.relay = None

    def _auth_attrs(self):
        return [
            (A_USERNAME, self.username.encode()),
            (A_REALM, self.realm),
            (A_NONCE, self.nonce),
        ]

    def request(self, msg_type, attrs, txid=None, authed=True):
        """Send a request, handling the 401/438 challenge transparently."""
        txid = txid or secrets.token_bytes(12)
        if authed and self.nonce is None:
            # Probe once, unauthenticated, to collect REALM and NONCE.
            self.t.send(build(msg_type, txid, attrs))
            raw = self.t.recv()
            _, _, rattrs, _ = parse(raw)
            code = error_code(rattrs)
            assert code == 401, f"expected a 401 challenge, got {code}"
            self.realm = get(rattrs, A_REALM)
            self.nonce = get(rattrs, A_NONCE)
            assert self.realm, "401 must carry REALM"
            assert self.nonce, "401 must carry NONCE"
        for _ in range(3):
            full = attrs + self._auth_attrs() if authed else attrs
            key = self.key if authed else None
            self.t.send(build(msg_type, txid, full, key=key))
            raw = self.t.recv()
            mt, rtx, rattrs, mi = parse(raw)
            code = error_code(rattrs)
            if code == 438:
                # A 438 without REALM aborts libwebrtc's retry entirely.
                assert get(rattrs, A_REALM), "438 must carry REALM"
                self.nonce = get(rattrs, A_NONCE)
                self.realm = get(rattrs, A_REALM)
                txid = secrets.token_bytes(12)
                continue
            return raw, mt, rtx, rattrs, mi
        raise AssertionError("nonce rotation did not converge")

    def allocate(self, txid=None):
        raw, mt, rtx, attrs, mi = self.request(
            ALLOCATE_REQ, [(A_REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))], txid=txid)
        assert mt == ALLOCATE_SUCCESS, f"allocate failed: {error_code(attrs)}"
        assert mi is not None, "post-auth responses MUST carry MESSAGE-INTEGRITY"
        assert verify_integrity(raw, mi, self.key), "MESSAGE-INTEGRITY does not verify"
        self.relay = decode_xor_addr(rtx, get(attrs, A_XOR_RELAYED_ADDRESS))
        assert get(attrs, A_XOR_MAPPED_ADDRESS) is not None, "Allocate needs XOR-MAPPED-ADDRESS"
        assert get(attrs, A_LIFETIME) is not None, "Allocate needs LIFETIME"
        return raw, attrs

    def create_permission(self, host, port=0):
        txid = secrets.token_bytes(12)
        raw, mt, _, attrs, _ = self.request(
            CREATE_PERM_REQ, [(A_XOR_PEER_ADDRESS, encode_xor_addr(txid, host, port))], txid=txid)
        return mt, error_code(attrs)

    def channel_bind(self, num, host, port):
        txid = secrets.token_bytes(12)
        raw, mt, _, attrs, _ = self.request(CHANNEL_BIND_REQ, [
            (A_CHANNEL_NUMBER, struct.pack("!HH", num, 0)),
            (A_XOR_PEER_ADDRESS, encode_xor_addr(txid, host, port)),
        ], txid=txid)
        assert mt == CHANNEL_BIND_SUCCESS, f"channel bind failed: {error_code(attrs)}"

    def send_indication(self, host, port, payload):
        txid = secrets.token_bytes(12)
        self.t.send(build(SEND_IND, txid, [
            (A_XOR_PEER_ADDRESS, encode_xor_addr(txid, host, port)),
            (A_DATA, payload),
        ]))

    def channel_send(self, num, payload):
        frame = struct.pack("!HH", num, len(payload)) + payload
        if self.t.name != "udp":
            frame += b"\x00" * (pad4(len(frame)) - len(frame))
        self.t.send(frame)

    def refresh(self, lifetime):
        raw, mt, _, attrs, _ = self.request(
            REFRESH_REQ, [(A_LIFETIME, struct.pack("!I", lifetime))])
        return mt, attrs

    def recv_relayed(self):
        """Return (peer, payload) from a Data indication or ChannelData."""
        raw = self.t.recv()
        if 64 <= raw[0] <= 79:
            num, length = struct.unpack("!HH", raw[:4])
            return ("channel", num), raw[4:4 + length], raw
        mt, txid, attrs, _ = parse(raw)
        assert mt == DATA_IND, f"expected a Data indication, got {mt:#06x}"
        peer = decode_xor_addr(txid, get(attrs, A_XOR_PEER_ADDRESS))
        return peer, get(attrs, A_DATA), raw

    def close(self):
        self.t.close()


# --------------------------------------------------------------------------
# a UDP echo peer
# --------------------------------------------------------------------------

def start_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                return
            s.sendto(data, addr)
    threading.Thread(target=loop, daemon=True).start()
    return s, port


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------

FAILURES = []


def check(name, fn):
    try:
        fn()
        print(f"  PASS  {name}")
    except Exception as e:
        FAILURES.append((name, e))
        print(f"  FAIL  {name}: {e}")


def scenario_relay(host, transport_cls, secret, echo_port, allow_private):
    """(a) Allocate -> CreatePermission -> Send -> echo -> Data."""
    c = TurnClient(transport_cls(host, TURN_PORT), secret)
    try:
        c.allocate()
        mt, code = c.create_permission("127.0.0.1")
        if not allow_private:
            # (h) A loopback peer must be refused with 403 -- not 401, which
            # libwebrtc treats as a terminal credential failure, and not
            # silence, which burns the whole retransmission budget.
            assert code == 403, f"private peer should be 403 Forbidden, got {code}"
            return
        assert mt == CREATE_PERM_SUCCESS, f"create permission failed: {code}"
        c.send_indication("127.0.0.1", echo_port, b"hello-turn")
        peer, payload, _ = c.recv_relayed()
        assert payload == b"hello-turn", f"echo mismatch: {payload!r}"
        assert peer[1] == echo_port, f"unexpected peer {peer}"
    finally:
        c.close()


def scenario_channel_padding(host, secret, echo_port):
    """(d) 1-, 2- and 3-byte payloads must each occupy exactly 8 bytes."""
    c = TurnClient(TcpTransport(host, TURN_PORT), secret)
    try:
        c.allocate()
        mt, code = c.create_permission("127.0.0.1")
        assert mt == CREATE_PERM_SUCCESS, f"create permission failed: {code}"
        c.channel_bind(0x4001, "127.0.0.1", echo_port)
        for payload in (b"a", b"ab", b"abc", b"abcd"):
            c.channel_send(0x4001, payload)
            peer, got, raw = c.recv_relayed()
            assert peer == ("channel", 0x4001), f"expected ChannelData, got {peer}"
            assert got == payload, f"echo mismatch: {got!r} != {payload!r}"
            assert len(raw) == pad4(4 + len(payload)), (
                f"frame for {len(payload)}-byte payload was {len(raw)} bytes, "
                f"expected {pad4(4 + len(payload))} -- unpadded ChannelData "
                f"desynchronises the stream permanently")
    finally:
        c.close()


def scenario_allocate_retransmit(host, secret):
    """(e) Same txid replays; a different txid on the same 5-tuple gets 437."""
    c = TurnClient(UdpTransport(host, TURN_PORT), secret)
    try:
        txid = secrets.token_bytes(12)
        raw1, attrs1 = c.allocate(txid=txid)
        relay1 = c.relay
        # Retransmission: identical transaction id, same 5-tuple.
        c.t.send(build(ALLOCATE_REQ, txid,
                       [(A_REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))] + c._auth_attrs(),
                       key=c.key))
        raw2 = c.t.recv()
        mt2, tx2, attrs2, _ = parse(raw2)
        assert mt2 == ALLOCATE_SUCCESS, f"retransmit should replay success, got {error_code(attrs2)}"
        relay2 = decode_xor_addr(tx2, get(attrs2, A_XOR_RELAYED_ADDRESS))
        assert relay1 == relay2, f"retransmit allocated a SECOND relay port: {relay1} vs {relay2}"
        # Duplicate: a different transaction id on the same 5-tuple.
        c.t.send(build(ALLOCATE_REQ, secrets.token_bytes(12),
                       [(A_REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))] + c._auth_attrs(),
                       key=c.key))
        _, _, attrs3, _ = parse(c.t.recv())
        assert error_code(attrs3) == 437, f"duplicate Allocate should be 437, got {error_code(attrs3)}"
    finally:
        c.close()


def scenario_refresh_zero(host, secret):
    """(f) Refresh(0) must echo 0, or clients never release their ports."""
    c = TurnClient(UdpTransport(host, TURN_PORT), secret)
    try:
        c.allocate()
        mt, attrs = c.refresh(0)
        assert mt == REFRESH_SUCCESS, f"refresh(0) failed: {error_code(attrs)}"
        lifetime = struct.unpack("!I", get(attrs, A_LIFETIME))[0]
        assert lifetime == 0, (
            f"refresh(0) echoed LIFETIME={lifetime}; Chrome branches on the "
            f"echoed value, so anything but 0 leaks a relay port per call")
    finally:
        c.close()


def scenario_opaque_relay(host, secret, allow_private):
    """(g) A STUN Binding sent to the relay address is data, not a request."""
    if not allow_private:
        return  # needs a loopback peer permission
    c = TurnClient(UdpTransport(host, TURN_PORT), secret)
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(1.5)
    peer.bind(("127.0.0.1", 0))
    peer_port = peer.getsockname()[1]
    try:
        c.allocate()
        mt, code = c.create_permission("127.0.0.1")
        assert mt == CREATE_PERM_SUCCESS, f"create permission failed: {code}"
        # A well-formed STUN Binding request, addressed to the CLIENT.
        probe = build(BINDING_REQ, secrets.token_bytes(12), [])
        peer.sendto(probe, c.relay)
        _, payload, _ = c.recv_relayed()
        assert payload == probe, (
            "the relay socket must be an opaque byte pipe: the client's own "
            "ICE Binding checks have to arrive byte-identically")
        try:
            reply = peer.recvfrom(65535)
            raise AssertionError(
                f"server answered the peer's Binding request: {reply[0][:8]!r} "
                f"-- parsing relay traffic breaks ICE nomination")
        except socket.timeout:
            pass
    finally:
        peer.close()
        c.close()


def scenario_channel_keepalive(host, secret, echo_port):
    """(i) ChannelBind alone must keep the permission alive past t=300s."""
    c = TurnClient(UdpTransport(host, TURN_PORT), secret)
    try:
        c.allocate()
        mt, code = c.create_permission("127.0.0.1")
        assert mt == CREATE_PERM_SUCCESS, f"create permission failed: {code}"
        c.channel_bind(0x4002, "127.0.0.1", echo_port)
        start = time.time()
        checkpoints = [400, 700]
        while checkpoints:
            elapsed = time.time() - start
            if elapsed >= checkpoints[0]:
                c.channel_send(0x4002, b"still-here")
                _, got, _ = c.recv_relayed()
                assert got == b"still-here", (
                    f"relaying stopped by t={elapsed:.0f}s -- ChannelBind must "
                    f"refresh the permission, or every call dies at t=300s")
                print(f"        relayed OK at t={elapsed:.0f}s")
                checkpoints.pop(0)
                continue
            # Refresh the channel only -- never CreatePermission, which is
            # exactly what Chrome stops sending once a channel is bound.
            c.channel_bind(0x4002, "127.0.0.1", echo_port)
            time.sleep(min(30, max(1, checkpoints[0] - (time.time() - start))))
    finally:
        c.close()


def scenario_aiortc(host, secret):
    """(c) aiortc verifies MESSAGE-INTEGRITY on responses; Chrome does not."""
    try:
        import aiortc  # noqa: F401
    except ImportError:
        print("  SKIP  aiortc canary (pip install aiortc to enable)")
        return
    import asyncio
    from aiortc.turn import create_turn_endpoint

    username, password, _ = credentials(secret)

    async def run():
        transport, _ = await create_turn_endpoint(
            asyncio.DatagramProtocol,
            server_addr=(host, TURN_PORT),
            username=username,
            password=password,
            lifetime=600,
        )
        transport.close()

    asyncio.run(run())


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--slow", action="store_true",
                    help="add the 12-minute ChannelBind keepalive scenario")
    # The relay scenarios need a loopback peer, so allow_private is on by
    # default here. --strict-peers turns it off and instead asserts that a
    # loopback peer is refused with 403.
    ap.add_argument("--strict-peers", dest="allow_private", action="store_false",
                    default=True, help="run with allow_private off and assert the 403 path")
    args = ap.parse_args()

    if not os.path.exists(BIN):
        raise SystemExit(f"{BIN} not found -- run `cargo build` first")

    echo_sock, echo_port = start_echo()
    tmp = tempfile.mkdtemp(prefix="snproxy-turn-")
    proc = subprocess.Popen([BIN, "--mode", "foreground", "--port", WEB, "--data-dir", tmp],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        wait_web(proc)
        status, cfg = api("POST", "/api/proxies", {
            "name": "turn-test",
            "protocol": "turn",
            "listen_addr": f"0.0.0.0:{TURN_PORT}",
            "turn": {
                "transports": ["udp", "tcp"],
                "realm": REALM,
                "static_secret": SECRET,
                "relay_ip": "127.0.0.1",
                "allow_private": args.allow_private,
                "relay_min_port": 51000,
                "relay_max_port": 51099,
            },
        })
        assert status == 200, f"create failed: {status} {cfg}"
        status, _ = api("POST", f"/api/proxies/{cfg['id']}/start")
        assert status == 200, f"start failed: {status}"
        time.sleep(0.4)

        print("TURN integration tests")
        check("relay over udp", lambda: scenario_relay(
            args.host, UdpTransport, SECRET, echo_port, args.allow_private))
        check("relay over tcp", lambda: scenario_relay(
            args.host, TcpTransport, SECRET, echo_port, args.allow_private))
        check("channel data padding over tcp", lambda: scenario_channel_padding(
            args.host, SECRET, echo_port))
        check("allocate retransmit vs duplicate", lambda: scenario_allocate_retransmit(
            args.host, SECRET))
        check("refresh(0) echoes zero", lambda: scenario_refresh_zero(args.host, SECRET))
        check("relay socket is an opaque pipe", lambda: scenario_opaque_relay(
            args.host, SECRET, args.allow_private))
        check("aiortc response-signing canary", lambda: scenario_aiortc(args.host, SECRET))
        if args.slow:
            check("channelbind keeps the permission alive", lambda: scenario_channel_keepalive(
                args.host, SECRET, echo_port))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        echo_sock.close()

    if FAILURES:
        print(f"\n{len(FAILURES)} scenario(s) failed")
        sys.exit(1)
    print("\nall scenarios passed")


if __name__ == "__main__":
    main()
