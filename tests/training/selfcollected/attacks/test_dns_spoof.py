from training.selfcollected.attacks.dns_spoof import build_command, parse_extra_args, run


def test_build_command_produces_expected_dnsspoof_invocation():
    cmd = build_command("eth0", "/tmp/hosts.txt")
    assert cmd == ["dnsspoof", "-i", "eth0", "-f", "/tmp/hosts.txt"]


def test_parse_extra_args_requires_interface_and_hosts_file():
    parsed = parse_extra_args(["--interface", "eth0", "--hosts-file", "/tmp/hosts.txt"])
    assert parsed["interface"] == "eth0"
    assert parsed["hosts_file"] == "/tmp/hosts.txt"
    assert parsed["duration"] == 60


def test_run_records_the_arp_spoof_prerequisite_in_params(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "training.selfcollected.attacks.dns_spoof.run_timed_subprocess",
        lambda cmd, duration: None,
    )
    record = run(
        "10.0.0.3", "10.0.0.2", tmp_path,
        interface="eth0", hosts_file="/tmp/hosts.txt",
    )
    assert "arp_spoof" in record.params["prerequisite"]
