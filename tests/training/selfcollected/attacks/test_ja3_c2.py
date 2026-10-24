import time

from training.selfcollected.attacks.common.listener import (
    generate_self_signed_cert, start_listener,
)
from training.selfcollected.attacks.ja3_c2 import connect, run


def test_connect_returns_a_tls_version_string(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    start_listener("127.0.0.1", 8444, cert_path, key_path)
    time.sleep(0.2)

    version = connect("127.0.0.1", 8444)
    assert version is not None and "TLS" in version


def test_run_dry_run_does_not_connect(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ja3_c2.connect",
        lambda host, port: called.append((host, port)) or "TLSv1.3",
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
