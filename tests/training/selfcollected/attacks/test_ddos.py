import json

from training.selfcollected.attacks.ddos import build_command, parse_extra_args, run


def test_build_command_is_a_udp_flood_and_differs_from_syn_flood():
    cmd = build_command("10.0.0.3", 80)
    assert cmd == ["hping3", "--udp", "--flood", "-V", "-p", "80", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"port": 80, "duration": 30}


def test_run_dry_run_skips_execution(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ddos.run_timed_subprocess",
        lambda cmd, duration: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
    # Dry runs never call body(), so there's nothing to merge the
    # single-source note from; run_attack's dry-run branch legitimately
    # has no notes since no real attack traffic was generated.
    assert record.notes == ""


def test_run_persists_single_source_note_to_attacks_jsonl(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "training.selfcollected.attacks.ddos.check_tools", lambda tools: None,
    )
    monkeypatch.setattr(
        "training.selfcollected.attacks.ddos.run_timed_subprocess",
        lambda cmd, duration: None,
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=False)
    assert record.status == "completed"
    assert record.notes == "single-attacker volumetric flood, not distributed"

    lines = (tmp_path / "attacks.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    persisted = json.loads(lines[0])
    assert persisted["notes"] == "single-attacker volumetric flood, not distributed"
