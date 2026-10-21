import json
import subprocess
import pytest

from training.selfcollected.attacks.common.runner import (
    AttackRecord,
    check_tools,
    append_record,
    run_subprocess,
)


def test_attack_record_to_json_line_round_trips():
    record = AttackRecord(
        attack="ssh_bruteforce", tool="hydra", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="2026-10-22T10:00:00Z",
        end_time="2026-10-22T10:01:00Z", status="completed",
        params={"port": 22},
    )
    line = record.to_json_line()
    parsed = json.loads(line)
    assert parsed["attack"] == "ssh_bruteforce"
    assert parsed["params"] == {"port": 22}
    assert parsed["notes"] == ""
    assert parsed["stderr_tail"] == ""


def test_check_tools_passes_when_all_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    check_tools(["hydra", "nmap"])  # should not raise


def test_check_tools_raises_with_missing_tool_name(monkeypatch):
    def fake_which(name):
        return None if name == "hydra" else f"/usr/bin/{name}"
    monkeypatch.setattr("shutil.which", fake_which)
    with pytest.raises(FileNotFoundError, match="hydra"):
        check_tools(["hydra", "nmap"])


def test_append_record_writes_one_jsonl_line_per_call(tmp_path):
    record1 = AttackRecord(
        attack="port_scan", tool="nmap", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="t1", end_time="t2",
        status="completed", params={},
    )
    record2 = AttackRecord(
        attack="syn_flood", tool="hping3", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="t3", end_time="t4",
        status="failed", params={}, stderr_tail="boom",
    )
    append_record(tmp_path, record1)
    append_record(tmp_path, record2)
    lines = (tmp_path / "attacks.jsonl").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["attack"] == "port_scan"
    assert json.loads(lines[1])["status"] == "failed"


def test_run_subprocess_succeeds_quietly_on_zero_exit():
    run_subprocess(["true"])  # should not raise


def test_run_subprocess_raises_called_process_error_with_stderr_on_failure():
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        run_subprocess(["python3", "-c", "import sys; sys.stderr.write('bad'); sys.exit(1)"])
    assert "bad" in exc_info.value.stderr
