from training.selfcollected.attacks.lateral_movement import build_command, parse_extra_args, run


def test_build_command_scans_the_target_with_service_enumeration():
    cmd = build_command("10.0.0.4", "1-1000")
    assert cmd == ["nmap", "-sS", "-sV", "-p", "1-1000", "10.0.0.4"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"ports": "1-1000"}


def test_run_dry_run_does_not_scan(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.lateral_movement.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.4", "10.0.0.3", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
