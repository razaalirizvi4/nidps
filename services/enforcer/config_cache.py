"""Short-TTL cache over common.config_loader.get() so FR-10.6 (apply config changes without
restart) is satisfied without re-querying SQLite on every verdict."""
from __future__ import annotations

import time
from typing import Callable, Union

from common import config_loader

Number = Union[int, float]


class CachedConfig:
    def __init__(
        self,
        conn,
        ttl_s: float = 5.0,
        now_fn: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._ttl_s = ttl_s
        self._now_fn = now_fn
        self._cache: dict[str, tuple[float, Union[Number, str, bool]]] = {}

    def get(self, key: str) -> Union[Number, str, bool]:
        now = self._now_fn()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        value = config_loader.get(self._conn, key)
        self._cache[key] = (now, value)
        return value
