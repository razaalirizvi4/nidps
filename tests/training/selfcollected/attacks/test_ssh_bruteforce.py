from training.selfcollected.attacks.ssh_bruteforce import build_command, parse_extra_args, run


def test_build_command_produces_expected_hydra_invocation():
    cmd = build_command("10.0.0.3", 22, "admin", "/tmp/wordlist.txt")
    assert cmd == ["hydra", "-l", "admin", "-P", "/tmp/wordlist.txt", "-s", "22", "10.0.0.3", "ssh"]


def test_parse_extra_args_defaults_when_nothing_passed():
    assert parse_extra_args([]) == {
        "port": 22, "username": "admin", "wordlist": "/usr/share/wordlists/rockyou.txt",
    }


def test_parse_extra_args_reads_overrides():
    parsed = parse_extra_args(["--port", "2222", "--username", "root", "--wordlist", "/tmp/w.txt"])
    assert parsed == {"port": 2222, "username": "root", "wordlist": "/tmp/w.txt"}


def test_run_dry_run_does_not_invoke_hydra(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ssh_bruteforce.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
