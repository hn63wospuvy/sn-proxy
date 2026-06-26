"""Minimal Shadowsocks AEAD (SIP004) client — smoke test for sn-proxy."""
import socket, hashlib, hmac, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# argv: [port] [password] [method]
HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1083
PASSWORD = (sys.argv[2] if len(sys.argv) > 2 else "sspass123").encode()
METHOD = sys.argv[3] if len(sys.argv) > 3 else "aes-256-gcm"
KEYLEN = 16 if METHOD == "aes-128-gcm" else 32


def make_aead(key):
    if METHOD == "chacha20-ietf-poly1305":
        return ChaCha20Poly1305(key)
    return AESGCM(key)


def evp_bytes_to_key(password, klen):
    d, prev = b"", b""
    while len(d) < klen:
        prev = hashlib.md5(prev + password).digest()
        d += prev
    return d[:klen]


def hkdf_sha1(key, salt, info, length):
    prk = hmac.new(salt, key, hashlib.sha1).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
        okm += t
        i += 1
    return okm[:length]


class Nonce:
    def __init__(self):
        self.n = 0
    def next(self):
        v = self.n.to_bytes(12, "little")
        self.n += 1
        return v


def encrypt_stream(aead, data):
    ctr, out = Nonce(), b""
    for i in range(0, len(data), 0x3FFF):
        piece = data[i:i + 0x3FFF]
        out += aead.encrypt(ctr.next(), len(piece).to_bytes(2, "big"), None)
        out += aead.encrypt(ctr.next(), piece, None)
    return out


def main():
    master = evp_bytes_to_key(PASSWORD, KEYLEN)

    # SOCKS5-form address for example.com:80
    host = b"example.com"
    addr = b"\x03" + bytes([len(host)]) + host + (80).to_bytes(2, "big")
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"

    s = socket.create_connection((HOST, PORT), timeout=15)

    tx_salt = os.urandom(KEYLEN)
    tx_aead = make_aead(hkdf_sha1(master, tx_salt, b"ss-subkey", KEYLEN))
    s.sendall(tx_salt + encrypt_stream(tx_aead, addr + request))

    # Response: server salt, then AEAD chunks.
    def recvn(n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    rx_salt = recvn(KEYLEN)
    if len(rx_salt) != KEYLEN:
        print("FAIL: no server salt"); sys.exit(1)
    rx_aead = make_aead(hkdf_sha1(master, rx_salt, b"ss-subkey", KEYLEN))
    ctr = Nonce()
    body = b""
    while True:
        enc_len = recvn(18)
        if len(enc_len) < 18:
            break
        ln = int.from_bytes(rx_aead.decrypt(ctr.next(), enc_len, None), "big")
        enc_payload = recvn(ln + 16)
        body += rx_aead.decrypt(ctr.next(), enc_payload, None)
    s.close()

    head = body.split(b"\r\n", 1)[0].decode("latin1")
    print("response status :", head)
    print("bytes received  :", len(body))
    ok = b"200" in head.encode() and b"Example Domain" in body
    print("RESULT          :", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
