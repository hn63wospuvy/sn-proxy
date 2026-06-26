"""A destination HTTPS server that *requires* a client certificate (mTLS).

It stands in for an upstream service behind mutual TLS. Every request is
answered with a line naming the client certificate it saw, so a test can
confirm sn-proxy presented the configured PKCS#12 client identity.

Listens on 127.0.0.1:9444.
"""

import http.server
import ssl
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST, PORT = "127.0.0.1", 9444


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _client_cn(self):
        cert = self.connection.getpeercert() or {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return "<none>"

    def do_GET(self):
        body = f"mtls-ok client={self._client_cn()}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(HERE / "dest.crt", HERE / "dest.key")
    ctx.load_verify_locations(HERE / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED  # demand a client certificate

    server = http.server.HTTPServer((HOST, PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"mTLS destination server listening on https://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
