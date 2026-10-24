"""Common extension point for every detection layer (FR-2 through FR-5). A new detector
implements this interface and publishes Evidence; DecisionEngine never needs to change."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from common.schemas import ComponentHealth, Evidence


class Detector(ABC):
    name: str

    @abstractmethod
    def analyse(self, item: Any) -> Optional[list[Evidence]]:
        """Return zero or more Evidence objects for the given input, or None."""

    @abstractmethod
    def heartbeat(self) -> ComponentHealth:
        """Return this detector's current health for the watchdog."""
