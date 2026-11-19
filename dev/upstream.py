"""Fake upstream server for testing MobileProxy locally (JSON + SOAP, gzip, ETag).

    python dev/upstream.py --port 9000
    python dev/upstream.py --port 9443 --tls      (self-signed cert generated via mitmproxy's certs module)
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import ssl
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

META = {"version": 7, "items": [{"id": 1, "name": "Sloup", "visible": True}, {"id": 2, "name": "Kabel", "visible": True}]}
SOAP = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><{op}Response xmlns="http://www.berit.com/wsdl/StatusService"><status>OK</status><code>200</code>'
        '</{op}Response></soap:Body></soap:Envelope>')


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        if "gzip" in self.headers.get("Accept-Encoding", "") and len(body) > 20:
            body = gzip.compress(body)
            extra = {**(extra or {}), "Content-Encoding": "gzip"}
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/meta"):
            if self.headers.get("If-None-Match") == '"v7"':
                self.send_response(304)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, json.dumps(META).encode(), "application/json; charset=utf-8", {"ETag": '"v7"'})
        elif self.path.startswith("/tile.png"):
            self._send(200, b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4, "image/png")
        else:
            self._send(404, b'{"error":"not found"}', "application/json")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.path.startswith("/StatusService"):
            m = re.search(r"<soap:Body>\s*<(\w+)", body)
            op = m.group(1) if m else "unknown"
            self._send(200, SOAP.format(op=op).encode(), "text/xml; charset=utf-8")
        else:
            self._send(200, json.dumps({"echo": body}).encode(), "application/json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--tls", action="store_true")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    if a.tls:
        from mitmproxy import certs
        ca = certs.CertStore.from_store(tempfile.mkdtemp(), "upstream", 2048)
        entry = ca.get_cert("localhost", ["localhost", "127.0.0.1"])
        d = tempfile.mkdtemp()
        open(f"{d}/c.pem", "wb").write(entry.cert.to_pem())
        open(f"{d}/k.pem", "wb").write(entry.privatekey.private_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PrivateFormat.TraditionalOpenSSL,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"upstream on {'https' if a.tls else 'http'}://127.0.0.1:{a.port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
