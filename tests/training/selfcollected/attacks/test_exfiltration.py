from training.selfcollected.attacks.exfiltration import build_payload, run


def test_build_payload_has_exact_requested_size():
    payload = build_payload(1024)
    assert len(payload) == 1024


def test_run_dry_run_does_not_send(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.exfiltration._send",
        lambda host, port, payload: called.append(len(payload)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"


def test_run_sends_requested_size(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.exfiltration._send",
        lambda host, port, payload: sent.append(len(payload)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, size_bytes=2048)
    assert sent == [2048]
    assert record.params["size_bytes"] == 2048
