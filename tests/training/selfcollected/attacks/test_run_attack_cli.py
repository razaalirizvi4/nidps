from training.selfcollected.attacks.run_attack import ATTACKS, main


def test_all_ten_attacks_are_registered():
    assert set(ATTACKS) == {
        "ssh_bruteforce", "port_scan", "arp_spoof", "dns_spoof", "syn_flood",
        "ja3_c2", "c2_beacon", "exfiltration", "ddos", "lateral_movement",
    }


def test_main_dry_run_exits_zero(tmp_path, capsys):
    exit_code = main([
        "port_scan", "--attacker-ip", "10.0.0.2", "--victim-ip", "10.0.0.3",
        "--out-dir", str(tmp_path), "--dry-run",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "dry_run" in captured.out
