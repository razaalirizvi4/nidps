import json
import time

from training.selfcollected.capture.capture_session import (
    new_session_dir, start_capture, stop_capture, run_benign_session, run_attack_session,
)


def test_new_session_dir_creates_a_timestamped_labelled_directory(tmp_path):
    session_dir = new_session_dir(tmp_path, "benign")
    assert session_dir.exists()
    assert session_dir.name.endswith("-benign")
    assert session_dir.parent == tmp_path


def test_start_and_stop_capture_terminates_a_long_running_process_quickly(tmp_path):
    # start_capture() is specified against tcpdump directly; stop_capture()'s
    # termination behaviour is generic, so it's tested here against a plain
    # `sleep` process instead, needing no root/network/tcpdump.
    import subprocess
    proc = subprocess.Popen(["sleep", "100"])
    start = time.monotonic()
    stop_capture(proc, grace_seconds=1.0)
    elapsed = time.monotonic() - start
    assert elapsed < 3
    assert proc.poll() is not None  # process has exited


def test_run_benign_session_writes_pcap_placeholder_and_manifest(tmp_path, monkeypatch):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps({"event_type": "alert", "timestamp": "2026-10-22T10:00:00Z"}) + "\n")

    class _FakeProc:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(
        "training.selfcollected.capture.capture_session.start_capture",
        lambda interface, pcap_path: pcap_path.write_bytes(b"") or _FakeProc(),
    )
    monkeypatch.setattr("time.sleep", lambda s: None)
    # Fix "now" so the session window brackets the fixture alert above,
    # regardless of the real wall-clock date the test happens to run on.
    monkeypatch.setattr(
        "training.selfcollected.capture.capture_session._utc_now_iso",
        lambda: "2026-10-22T10:00:00Z",
    )

    session_dir = run_benign_session(tmp_path, "vboxnet0", duration_s=0.1, eve_path=eve_path)
    assert (session_dir / "session.pcap").exists()
    manifest = json.loads((session_dir / "benign_session_manifest.json").read_text())
    assert manifest["excluded_count"] == 1


def test_run_attack_session_wraps_capture_around_one_attack_run(tmp_path, monkeypatch):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text("")

    class _FakeProc:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(
        "training.selfcollected.capture.capture_session.start_capture",
        lambda interface, pcap_path: pcap_path.write_bytes(b"") or _FakeProc(),
    )
    monkeypatch.setattr("time.sleep", lambda s: None)

    class _FakeAttackModule:
        __name__ = "training.selfcollected.attacks.port_scan"

        @staticmethod
        def run(out_dir, **kwargs):
            (out_dir / "attacks.jsonl").write_text('{"attack": "port_scan", "status": "completed"}\n')
            return {"status": "completed", "kwargs_received": kwargs}

    session_dir, record = run_attack_session(
        base_dir=tmp_path,
        interface="vboxnet0",
        attack_module=_FakeAttackModule,
        attack_kwargs={
            "attack_name": "port_scan", "victim_ip": "10.0.0.3", "attacker_ip": "10.0.0.2",
        },
        eve_path=eve_path,
        settle_s=0.0,
    )
    assert (session_dir / "session.pcap").exists()
    assert (session_dir / "attacks.jsonl").exists()
    assert record["status"] == "completed"
    assert record["kwargs_received"] == {"victim_ip": "10.0.0.3", "attacker_ip": "10.0.0.2"}
