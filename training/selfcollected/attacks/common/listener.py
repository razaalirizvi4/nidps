"""Minimal attacker-side TLS listener for ja3_c2.py and c2_beacon.py to connect to."""

import http.server
import ssl
import subprocess
import threading
from pathlib import Path


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-nodes",
            "-subj", "/CN=nidps-lab-c2-listener",
        ],
        check=True, capture_output=True,
    )


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - matches BaseHTTPRequestHandler signature
        pass  # keep test/attack output quiet; connections are logged by the caller if needed

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


class _QuietServer(http.server.HTTPServer):
    def handle_error(self, request, client_address):  # noqa: ARG002 - matches socketserver signature
        pass  # suppress expected errors (e.g., BrokenPipeError from incomplete TLS handshakes in tests)


def start_listener(host: str, port: int, cert_path: Path, key_path: Path) -> threading.Thread:
    """Starts a minimal HTTPS listener on a daemon thread and returns it immediately."""
    server = _QuietServer((host, port), _QuietHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
