"""Algorithm 5.3: ARP consistency checking. onArp() returns list[Evidence] (possibly more than
one per frame, and possibly empty) -- see this plan's Global Constraints for why this deviates
from the UML's literal singular-Evidence signature; analyse() wraps it to satisfy the Detector
ABC exactly."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common.detector import Detector
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer, utc_now_iso


@dataclass
class ArpFrame:
    sender_ip: str
    sender_mac: str
    is_reply: bool
    is_gratuitous: bool
    timestamp: float


class ArpMonitor(Detector):
    name = "arpmon"

    def __init__(
        self,
        gateway_ip: str,
        ap_mac: str,
        flood_threshold_n: int = 10,
        flood_window_s: float = 10.0,
    ) -> None:
        self.bindings: dict = {}
        self.gateway_ip = gateway_ip
        self.ap_mac = ap_mac.lower()
        self.flood_threshold_n = flood_threshold_n
        self.flood_window_s = flood_window_s
        self._reply_times: dict = {}

    def refreshBindings(self, leases: dict) -> None:
        self.bindings = dict(leases)

    def onArp(self, frame: ArpFrame) -> list:
        if not (frame.is_reply or frame.is_gratuitous):
            return []

        evidence = []
        sender_mac = frame.sender_mac.lower()

        bound_mac = self.bindings.get(frame.sender_ip)
        if bound_mac is not None and bound_mac.lower() != sender_mac:
            evidence.append(self._make_evidence(frame, signature_id=1))

        if frame.sender_ip == self.gateway_ip and sender_mac != self.ap_mac:
            evidence.append(self._make_evidence(frame, signature_id=2))

        history = self._reply_times.setdefault(sender_mac, [])
        history.append(frame.timestamp)
        window_start = frame.timestamp - self.flood_window_s
        while history and history[0] < window_start:
            history.pop(0)
        if len(history) > self.flood_threshold_n:
            evidence.append(self._make_evidence(frame, signature_id=3))

        return evidence

    def _make_evidence(self, frame: ArpFrame, signature_id: int) -> Evidence:
        return Evidence(
            source=Layer.ARP,
            flow_id=None,
            host_ip=frame.sender_ip,
            kind=EvidenceType.SIGNATURE,
            strength=1.0,
            weight=0.0,  # services/arpmon/main.py fills this from risk.weight_signature
            signature_id=signature_id,
        )

    def analyse(self, item: ArpFrame) -> Optional[list]:
        result = self.onArp(item)
        return result or None

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
