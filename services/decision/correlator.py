"""Groups Evidence by flow so Algorithm 5.5 sees everything known about one flow together.

Evidence with no flow_id (Layer 1 alerts, ARP, exfiltration, beaconing) cannot be matched to a
flow, so each item is released as its own group immediately. Evidence with a flow_id is held for
`window_s` after the first item for that flow arrives, then released together. A signature
match at strength 1.0 (a drop rule or severity-1 alert) skips the wait, because Algorithm 5.5
blocks on it whatever the other layers say."""
from __future__ import annotations

import time
from typing import Callable

from common.schemas import Evidence, EvidenceType


def is_hard_signature(ev: Evidence) -> bool:
    return ev.kind == EvidenceType.SIGNATURE and ev.strength >= 1.0


class EvidenceCorrelator:
    def __init__(self, window_s: float = 3.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._window_s = window_s
        self._clock = clock
        self._pending: dict = {}  # str(flow_id) -> (first_seen, [Evidence])

    def add(self, ev: Evidence) -> list:
        """Returns the groups that are ready to decide now."""
        if ev.flow_id is None:
            return [[ev]]
        key = str(ev.flow_id)
        first_seen, items = self._pending.get(key, (self._clock(), []))
        items.append(ev)
        if is_hard_signature(ev):
            self._pending.pop(key, None)
            return [items]
        self._pending[key] = (first_seen, items)
        return []

    def flush_due(self) -> list:
        now = self._clock()
        due = [k for k, (first_seen, _) in self._pending.items() if now - first_seen >= self._window_s]
        return [self._pending.pop(k)[1] for k in due]

    def flush_all(self) -> list:
        groups = [items for _, items in self._pending.values()]
        self._pending.clear()
        return groups
