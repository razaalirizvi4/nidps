"""Parses Suricata eve.json alert events into exclusion windows for benign-capture labelling.

Used so the benign capture session (§5.2.2) can flag windows that Suricata already
considers malicious, per the calibration exclusion logic in §5.5.2 — this module only
flags them; actual exclusion happens in the training pipeline (Phase 7), not here.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _parse_timestamp(ts: str) -> datetime:
    """Parses an ISO-8601 timestamp into a tz-aware datetime.

    Handles both timestamp styles seen in this codebase:
      - Suricata eve.json's own format, e.g. "2026-10-22T10:01:00.000000+0000"
        (a trailing numeric UTC offset with no colon).
      - This repo's `_utc_now_iso()` format, e.g. "2026-10-22T10:00:00Z"
        (a bare trailing "Z").
    """
    normalized = ts.strip()
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        else:
            # Insert a colon into a trailing 4-digit +HHMM/-HHMM offset,
            # e.g. "+0000" -> "+00:00", so fromisoformat can parse it.
            normalized = re.sub(
                r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized,
            )
        dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


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
    start_dt = _parse_timestamp(session_start)
    end_dt = _parse_timestamp(session_end)
    in_window = [
        (s, e) for s, e in alert_windows
        if start_dt <= _parse_timestamp(s) <= end_dt
    ]
    return {
        "session_start": session_start,
        "session_end": session_end,
        "excluded_windows": [{"start": s, "end": e} for s, e in in_window],
        "excluded_count": len(in_window),
    }
