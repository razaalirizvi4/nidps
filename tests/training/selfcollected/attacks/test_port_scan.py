from training.selfcollected.attacks.port_scan import build_command, parse_extra_args, run


def test_build_command_produces_expected_nmap_invocation():
    cmd = build_command("10.0.0.3", "1-1000", "-sS")
    assert cmd == ["nmap", "-sS", "-p", "1-1000", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"ports": "1-1000", "scan_type": "-sS"}


def test_parse_extra_args_overrides():
    assert parse_extra_args(["--ports", "1-65535", "--scan-type", "-sT"]) == {
        "ports": "1-65535", "scan_type": "-sT",
    }


def test_run_dry_run_does_not_invoke_nmap(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.port_scan.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
