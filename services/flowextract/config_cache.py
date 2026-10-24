"""5-second-TTL cache over common.config_loader.get() so FlowAssembler's timeouts (FR-10.6) and
the retention purge interval can change at runtime without restarting this service. Deliberately
duplicated (not imported from another phase's package) in services/mlscorer/config_cache.py
(Task 17) -- each phase in this plan owns its own tiny dependency-free copy, matching the
precedent set by the decision-fusion phase's services/enforcer/config_cache.py."""
from __future__ import annotations

import time
from typing import Callable

from common import config_loader


class CachedConfig:
    def __init__(
        self, conn, ttl_s: float = 5.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._conn = conn
        self._ttl_s = ttl_s
        self._clock = clock
        self._cache: dict = {}

    def get(self, key: str):
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        value = config_loader.get(self._conn, key)
        self._cache[key] = (now, value)
        return value
