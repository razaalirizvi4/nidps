"""Algorithm 5.5 (per-flow verdict) and Eq 5.8 host accumulation, FR-6.x.

decide() takes every Evidence the correlator grouped for one flow (or one flow-less item) and
returns a Decision: the Verdict plus the host's updated score. It does no I/O; main.py publishes.

How the evidence maps onto the algorithm's symbols:
  A(f) has a drop rule / severity 1  -> SIGNATURE evidence with strength >= 1.0 (Layer 1 or ARP)
  A(f) != empty                      -> any SIGNATURE evidence
  s(f) >= tau                        -> ANOMALY evidence (Layer 2 only publishes past its own tau)
  y, c                               -> predicted_class / confidence of the most confident CLASS
                                        evidence. "Benign", "Unknown", a missing class and c below
                                        theta_c all count as "not an attack".
EXFIL and BEACON evidence is treated like ANOMALY: it raises an alert and feeds the host score.
With no Layer 3 running there is no CLASS evidence, so only the L1 block, the host-score block and
ALERT paths can fire.

Evidence from a layer switched off with detection.layerN_enabled is dropped before any of this
(FR-10.1). Every threshold and weight is read through the config cache on each call, so a change
in the dashboard applies within the cache TTL, without a restart (FR-10.6).

Deviations from the literal pseudocode, both deliberate:
  * Evidence is added to the host score on every non-PASS outcome, not only on the ALERT path, so
    a host blocked by Layer 1 still shows a raised risk level on the dashboard.
  * When the host score reaches risk.block_threshold the flow becomes BLOCK (layer HOST, FR-6.4)
    and that host's score is reset to zero. Without the reset every later flow from the host
    would be another BLOCK, and the enforcer counts blocks to set its back-off duration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common.schemas import (
    Action,
    EvidenceType,
    HostScore,
    Layer,
    Verdict,
    utc_now_iso,
)
from services.decision.correlator import is_hard_signature

# FR-10.1: which detection.layerN_enabled switch controls which evidence source. ARP detection is
# a signature-style check, so it follows the Layer 1 switch.
_LAYER_SWITCH = {
    Layer.L1_SIGNATURE: "detection.layer1_enabled",
    Layer.ARP: "detection.layer1_enabled",
    Layer.L2_ANOMALY: "detection.layer2_enabled",
    Layer.L3_CLASSIFIER: "detection.layer3_enabled",
}
_NOT_ATTACK = {None, "Benign", "Unknown"}
_ANOMALY_KINDS = {EvidenceType.ANOMALY, EvidenceType.EXFIL, EvidenceType.BEACON}


@dataclass
class Decision:
    verdict: Verdict
    host_score: Optional[HostScore]


def _unique_layers(evidence: list) -> list:
    seen = []
    for ev in evidence:
        if ev.source not in seen:
            seen.append(ev.source)
    return seen


class DecisionEngine:
    def __init__(self, risk, allowlist, config) -> None:
        """risk: RiskScoreTracker. allowlist: object with contains(ip). config: object with
        get(key), e.g. services.flowextract.config_cache.CachedConfig."""
        self._risk = risk
        self._allowlist = allowlist
        self._config = config

    def _best_class(self, group: list, theta_c: float) -> tuple:
        classes = [e for e in group if e.kind == EvidenceType.CLASS]
        if not classes:
            return None, 0.0, None
        best = max(classes, key=lambda e: e.confidence or 0.0)
        c = best.confidence or 0.0
        y = best.predicted_class if c >= theta_c else "Unknown"
        return y, c, best

    def decide(self, group: list) -> Decision:
        host_ip = group[0].host_ip
        flow_id = next((e.flow_id for e in group if e.flow_id is not None), None)
        flow_id = None if flow_id is None else str(flow_id)

        def verdict(action, layers, why, attack_class=None) -> Verdict:
            return Verdict(
                action=action, layers=layers, explanation=why,
                flow_id=flow_id, host_ip=host_ip, attack_class=attack_class,
            )

        if not host_ip:
            return Decision(verdict(Action.PASS, [], "evidence has no source address"), None)
        if self._allowlist.contains(host_ip):
            return Decision(verdict(Action.PASS, [], f"{host_ip} is on the allowlist"), None)

        # Evidence from a layer the administrator has switched off is ignored (FR-10.1).
        enabled = [e for e in group if self._config.get(_LAYER_SWITCH[e.source])]
        if not enabled:
            return Decision(verdict(Action.PASS, [], "evidence came only from disabled layers"), None)
        group = enabled

        theta_block = self._config.get("fusion.theta_block")
        theta_alert = self._config.get("fusion.theta_alert")
        theta_c = self._config.get("fusion.theta_c")
        y, c, class_ev = self._best_class(group, theta_c)
        is_attack = y not in _NOT_ATTACK

        hard = [e for e in group if is_hard_signature(e)]
        anomaly = [e for e in group if e.kind in _ANOMALY_KINDS]
        signature = [e for e in group if e.kind == EvidenceType.SIGNATURE]
        confident_class = is_attack and c >= theta_alert

        # Everything that counts as evidence against the host feeds its score.
        counted = list(signature) + list(anomaly) + ([class_ev] if confident_class else [])
        score = None
        if counted:
            now = utc_now_iso()
            for ev in counted:
                score = self._risk.add(host_ip, ev.weight, ev.timestamp or now)

        def host_score() -> Optional[HostScore]:
            return None if score is None else HostScore(host_ip=host_ip, score=score)

        if hard:
            sigs = ", ".join(str(e.signature_id) for e in hard if e.signature_id is not None)
            why = "drop-rule or severity-1 match" + (f" (signature {sigs})" if sigs else "")
            return Decision(verdict(Action.BLOCK, _unique_layers(hard), why), host_score())

        if is_attack and c >= theta_block:
            return Decision(
                verdict(Action.BLOCK, [Layer.L3_CLASSIFIER],
                        f"classified {y} with confidence {c:.2f}", y),
                host_score(),
            )

        if anomaly and confident_class:
            return Decision(
                verdict(Action.BLOCK, [Layer.L2_ANOMALY, Layer.L3_CLASSIFIER],
                        f"anomaly agrees with classification {y} (confidence {c:.2f})", y),
                host_score(),
            )

        if counted:
            threshold = self._config.get("risk.block_threshold")
            if score >= threshold:
                self._risk.reset(host_ip)
                return Decision(
                    verdict(Action.BLOCK, [Layer.HOST] + _unique_layers(counted),
                            f"host risk score {score:.1f} reached the block threshold {threshold:.1f}",
                            y if is_attack else None),
                    HostScore(host_ip=host_ip, score=0.0),
                )
            kinds = ", ".join(sorted({e.kind.value for e in counted}))
            return Decision(
                verdict(Action.ALERT, _unique_layers(counted),
                        f"{kinds} evidence; host risk score {score:.1f}", y if is_attack else None),
                host_score(),
            )

        return Decision(verdict(Action.PASS, [], "evidence below alert thresholds"), None)
