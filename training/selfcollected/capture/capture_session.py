"""Orchestrates one benign or attack capture session (§5.2.2).

Every session directory ends up with session.pcap plus either
attacks.jsonl (attack sessions) or benign_session_manifest.json (benign
sessions). This module does not produce labelled flow records — that is
deferred to the flow extractor (Phase 2), out of scope here.
"""

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from training.selfcollected.attacks.common.runner import AttackRecord
from training.selfcollected.capture.eve_parser import build_benign_manifest


def new_session_dir(base_dir: Path, label: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_dir = base_dir / f"{ts}-{label}"
    session_dir.mkdir(parents=True, exist_ok=False)
    return session_dir


def start_capture(interface: str, pcap_path: Path) -> subprocess.Popen:
    return subprocess.Popen(
        ["tcpdump", "-i", interface, "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def stop_capture(proc: subprocess.Popen, grace_seconds: float = 2.0) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_benign_session(base_dir: Path, interface: str, duration_s: float, eve_path: Path) -> Path:
    session_dir = new_session_dir(base_dir, "benign")
    start = _utc_now_iso()
    capture = start_capture(interface, session_dir / "session.pcap")
    time.sleep(duration_s)
    stop_capture(capture)
    end = _utc_now_iso()
    manifest = build_benign_manifest(eve_path, start, end)
    (session_dir / "benign_session_manifest.json").write_text(json.dumps(manifest, indent=2))
    return session_dir


def run_attack_session(
    base_dir: Path,
    interface: str,
    attack_module: Any,
    attack_kwargs: dict,
    eve_path: Path,
    settle_s: float = 3.0,
) -> tuple[Path, AttackRecord]:
    """Runs one attack capture session and returns (session_dir, AttackRecord).

    `eve_path` is accepted for API symmetry with `run_benign_session`, but
    attack sessions do not currently copy or trim eve.json into the session
    directory, nor do they build a manifest from it -- that only happens for
    benign sessions. It is unused here today; wiring it up is out of scope
    for this fix.
    """
    attack_name = attack_kwargs.get("attack_name") or getattr(attack_module, "__name__", "attack")
    session_dir = new_session_dir(base_dir, attack_name.rsplit(".", 1)[-1])
    capture = start_capture(interface, session_dir / "session.pcap")
    try:
        kwargs = {k: v for k, v in attack_kwargs.items() if k != "attack_name"}
        record = attack_module.run(out_dir=session_dir, **kwargs)
    finally:
        time.sleep(settle_s)
        stop_capture(capture)
    return session_dir, record
