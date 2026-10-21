from training.selfcollected.attacks.arp_spoof import build_commands, parse_extra_args, run


def test_build_commands_produces_both_directions_of_poisoning():
    poison_victim, poison_gateway = build_commands("eth0", "10.0.0.3", "10.0.0.1")
    assert poison_victim == ["arpspoof", "-i", "eth0", "-t", "10.0.0.3", "10.0.0.1"]
    assert poison_gateway == ["arpspoof", "-i", "eth0", "-t", "10.0.0.1", "10.0.0.3"]


def test_parse_extra_args_requires_gateway_and_interface():
    parsed = parse_extra_args(["--gateway-ip", "10.0.0.1", "--interface", "eth0"])
    assert parsed["gateway_ip"] == "10.0.0.1"
    assert parsed["interface"] == "eth0"
    assert parsed["duration"] == 60  # default


def test_run_dry_run_spawns_no_processes(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.arp_spoof.subprocess.Popen",
        lambda cmd, **kw: called.append(cmd),
    )
    record = run(
        "10.0.0.3", "10.0.0.2", tmp_path,
        gateway_ip="10.0.0.1", interface="eth0", dry_run=True,
    )
    assert called == []
    assert record.status == "dry_run"
