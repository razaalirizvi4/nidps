"""Running mean/sample-variance/min/max/count accumulator (Welford's method), so flow features
(FR-3.3) are computed from a handful of floats per flow instead of storing every packet (NFR-14).
Uses SAMPLE variance (M2 / (n-1), n >= 2) consistently -- see this plan's Global Constraints."""
from __future__ import annotations

import math


class WelfordAccumulator:
    def __init__(self) -> None:
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._total = 0.0
        self._min = 0.0
        self._max = 0.0

    def add(self, x: float) -> None:
        self._count += 1
        if self._count == 1:
            self._mean = x
            self._m2 = 0.0
            self._min = x
            self._max = x
        else:
            delta = x - self._mean
            self._mean += delta / self._count
            self._m2 += delta * (x - self._mean)
            self._min = min(self._min, x)
            self._max = max(self._max, x)
        self._total += x

    @property
    def count(self) -> int:
        return self._count

    @property
    def total(self) -> float:
        return self._total

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        if self._count < 2:
            return 0.0
        return self._m2 / (self._count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def minimum(self) -> float:
        return self._min

    @property
    def maximum(self) -> float:
        return self._max
