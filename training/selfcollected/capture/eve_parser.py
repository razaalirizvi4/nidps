"""Parses Suricata eve.json alert events into exclusion windows for benign-capture labelling.

Used so the benign capture session (§5.2.2) can flag windows that Suricata already
considers malicious, per the calibration exclusion logic in §5.5.2 — this module only
flags them; actual exclusion happens in the training pipeline (Phase 7), not here.
"""

import json
from pathlib import Path


def parse_alert_windows(eve_path: Path) -> list[tuple[str, str]]:
    windows: list[tuple[str, str]] = []
    if not eve_path.exists():
        return windows
    with eve_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            ts = event["timestamp"]
            windows.append((ts, ts))
    return windows


def build_benign_manifest(eve_path: Path, session_start: str, session_end: str) -> dict:
    alert_windows = parse_alert_windows(eve_path)
    return {
        "session_start": session_start,
        "session_end": session_end,
        "excluded_windows": [{"start": s, "end": e} for s, e in alert_windows],
        "excluded_count": len(alert_windows),
    }
