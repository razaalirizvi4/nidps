"""ISO-8601 <-> epoch-seconds helpers shared by services/enforcer/enforcer.py and
services/decision/risk_tracker.py."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Callable

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def parse_iso(ts: str) -> datetime:
    return datetime.strptime(ts, ISO_FORMAT).replace(tzinfo=timezone.utc)


def format_iso(dt: datetime) -> str:
    return dt.strftime(ISO_FORMAT)


def iso_to_epoch(ts: str) -> float:
    return parse_iso(ts).timestamp()


def add_seconds_iso(ts: str, seconds: float) -> str:
    return format_iso(parse_iso(ts) + timedelta(seconds=seconds))


def epoch_hours_ago_iso(hours: float, now_fn: Callable[[], float] = time.time) -> str:
    now_dt = datetime.fromtimestamp(now_fn(), tz=timezone.utc)
    return format_iso(now_dt - timedelta(hours=hours))
