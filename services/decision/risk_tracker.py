"""Eq 5.8: per-host decaying risk score S_h(t) = S_h(t_prev) * exp(-lambda * dt) + w_v, with
lambda = ln2 / half_life. Pure state and arithmetic: no bus or database access, so the engine
decides when to publish. Time comes from the evidence timestamps (event time); a timestamp that
is earlier than the last one seen for that host is treated as dt = 0 rather than growing the
score."""
from __future__ import annotations

import math
from typing import Callable

from services.decision.time_utils import iso_to_epoch

# A decayed score below this is indistinguishable from zero on the dashboard.
_NEGLIGIBLE = 0.01


class RiskScoreTracker:
    def __init__(self, half_life_s: Callable[[], float]) -> None:
        # Callable so risk.half_life_s can be hot-reloaded (FR-10.6) between calls.
        self._half_life_s = half_life_s
        self._state: dict = {}  # host_ip -> (score, epoch of last update)

    def _decayed(self, host_ip: str, now: float) -> float:
        prev = self._state.get(host_ip)
        if prev is None:
            return 0.0
        score, t_prev = prev
        dt = max(0.0, now - t_prev)
        return score * math.exp(-math.log(2) / self._half_life_s() * dt)

    def add(self, host_ip: str, weight: float, timestamp_iso: str) -> float:
        now = iso_to_epoch(timestamp_iso)
        t_prev = self._state[host_ip][1] if host_ip in self._state else now
        score = self._decayed(host_ip, now) + weight
        self._state[host_ip] = (score, max(now, t_prev))
        return score

    def current(self, host_ip: str, timestamp_iso: str) -> float:
        return self._decayed(host_ip, iso_to_epoch(timestamp_iso))

    def reset(self, host_ip: str) -> None:
        self._state.pop(host_ip, None)

    def snapshot(self, timestamp_iso: str) -> dict:
        """Decayed score of every tracked host. Hosts that have decayed to ~0 are reported once
        as 0.0 and then forgotten, so the dashboard sees the score fall to zero."""
        now = iso_to_epoch(timestamp_iso)
        result = {}
        for host_ip in list(self._state):
            score = self._decayed(host_ip, now)
            if score < _NEGLIGIBLE:
                result[host_ip] = 0.0
                del self._state[host_ip]
            else:
                result[host_ip] = score
        return result
