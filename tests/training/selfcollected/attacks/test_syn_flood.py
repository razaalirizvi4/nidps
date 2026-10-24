from training.selfcollected.attacks.syn_flood import build_command, parse_extra_args, run


def test_build_command_is_a_tcp_syn_flood():
    cmd = build_command("10.0.0.3", 80)
    assert cmd == ["hping3", "-S", "--flood", "-V", "-p", "80", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"port": 80, "duration": 30}


def test_run_dry_run_skips_execution(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.syn_flood.run_timed_subprocess",
        lambda cmd, duration: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
