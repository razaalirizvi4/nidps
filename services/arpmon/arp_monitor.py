"""Algorithm 5.3: ARP consistency checking. onArp() returns list[Evidence] (possibly more than
one per frame, and possibly empty) -- see this plan's Global Constraints for why this deviates
from the UML's literal singular-Evidence signature; analyse() wraps it to satisfy the Detector
ABC exactly.

Per-MAC flood tracking (I7): _reply_times is keyed by sender MAC so it can grow without bound
over a long-running process, and an attacker who randomizes the source MAC on every reply never
accumulates enough entries under any one MAC to cross flood_threshold_n (a MAC-randomized "ARP
storm" evades per-MAC detection entirely). Two mitigations: (1) a periodic sweep every
_CLEANUP_INTERVAL calls to onArp() prunes and drops any MAC whose history is empty relative to
the current frame's timestamp, so one-off MACs don't persist forever; (2) a single global (not
per-MAC) reply-time window additionally flags a storm spread across many distinct MACs once the
combined rate crosses a conservative multiple of flood_threshold_n."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Optional

from common.detector import Detector
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer, utc_now_iso

_CLEANUP_INTERVAL = 100
_GLOBAL_FLOOD_MULTIPLIER = 5


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
        self._global_reply_times: deque = deque()
        self._cleanup_counter = 0

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

        window_start = frame.timestamp - self.flood_window_s

        history = self._reply_times.setdefault(sender_mac, deque())
        history.append(frame.timestamp)
        while history and history[0] < window_start:
            history.popleft()
        if len(history) > self.flood_threshold_n:
            evidence.append(self._make_evidence(frame, signature_id=3))

        self._global_reply_times.append(frame.timestamp)
        while self._global_reply_times and self._global_reply_times[0] < window_start:
            self._global_reply_times.popleft()
        if len(self._global_reply_times) > self.flood_threshold_n * _GLOBAL_FLOOD_MULTIPLIER:
            # A storm spread across many randomized MACs, invisible to the per-MAC check above.
            evidence.append(self._make_evidence(frame, signature_id=3))

        self._cleanup_counter += 1
        if self._cleanup_counter >= _CLEANUP_INTERVAL:
            self._cleanup_counter = 0
            self._sweep_stale_mac_histories(window_start)

        return evidence

    def _sweep_stale_mac_histories(self, window_start: float) -> None:
        """Periodic cleanup (I7): _reply_times never otherwise drops a MAC once seen, even
        after its whole history has aged out of the flood window -- that leaks memory
        unboundedly over a long-running process. Runs every _CLEANUP_INTERVAL calls to onArp()
        rather than on every call, to keep the common path O(1)."""
        for mac in list(self._reply_times.keys()):
            history = self._reply_times[mac]
            while history and history[0] < window_start:
                history.popleft()
            if not history:
                del self._reply_times[mac]

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
