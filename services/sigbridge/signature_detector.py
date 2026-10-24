"""FR-2.6: converts one Suricata eve.json alert into Evidence. severity_to_strength() implements
the drop/severity-1 -> 1.0 convention the decision-fusion phase's Algorithm 5.5 notes already
assume this component follows."""
from __future__ import annotations

from typing import Optional

from common.detector import Detector
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer, utc_now_iso

_SEVERITY_STRENGTH = {2: 0.6, 3: 0.3}
_DEFAULT_STRENGTH = 0.25


def severity_to_strength(severity: Optional[int], action: Optional[str]) -> float:
    if action == "drop" or severity == 1:
        return 1.0
    return _SEVERITY_STRENGTH.get(severity, _DEFAULT_STRENGTH)


class SignatureDetector(Detector):
    name = "sigbridge"

    def ingestEveAlert(self, alert: dict) -> Evidence:
        alert_block = alert.get("alert", {})
        severity = alert_block.get("severity")
        action = alert_block.get("action")
        return Evidence(
            source=Layer.L1_SIGNATURE,
            flow_id=None,
            host_ip=alert.get("src_ip", ""),
            kind=EvidenceType.SIGNATURE,
            strength=severity_to_strength(severity, action),
            weight=0.0,  # services/sigbridge/main.py fills this from risk.weight_signature
            signature_id=alert_block.get("signature_id"),
        )

    def analyse(self, item: dict) -> Optional[list]:
        return [self.ingestEveAlert(item)]

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
