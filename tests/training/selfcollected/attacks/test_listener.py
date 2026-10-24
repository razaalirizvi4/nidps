import socket
import ssl
import time

from training.selfcollected.attacks.common.listener import (
    generate_self_signed_cert,
    start_listener,
)


def test_generate_self_signed_cert_creates_both_files(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    assert cert_path.exists() and cert_path.stat().st_size > 0
    assert key_path.exists() and key_path.stat().st_size > 0


def test_start_listener_accepts_a_tls_connection(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)

    thread = start_listener("127.0.0.1", 8443, cert_path, key_path)
    time.sleep(0.2)  # let the listener bind

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls_sock:
            assert tls_sock.version() is not None

    assert thread.is_alive()  # daemon thread keeps serving further connections
