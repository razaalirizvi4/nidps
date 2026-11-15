"""ISO 8601 <-> epoch helpers for the decision engine (UTC, the format utc_now_iso() produces)."""
from __future__ import annotations

from datetime import datetime, timezone

_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def iso_to_epoch(iso_str: str) -> float:
    return datetime.strptime(iso_str, _FMT).replace(tzinfo=timezone.utc).timestamp()
