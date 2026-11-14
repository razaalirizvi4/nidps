import pytest

from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import Action, Evidence, EvidenceType, Layer
from services.decision.allowlist import Allowlist
from services.decision.engine import DecisionEngine
from services.decision.risk_tracker import RiskScoreTracker
from services.flowextract.config_cache import CachedConfig

HOST = "10.0.0.57"


def _engine(allowlisted=()):
    conn = connect(":memory:")
    seed_defaults(conn)
    for a in allowlisted:
        conn.execute("INSERT INTO allowlist_entry (address) VALUES (?)", (a,))
    conn.commit()
    config = CachedConfig(conn)
    risk = RiskScoreTracker(half_life_s=lambda: config.get("risk.half_life_s"))
    return DecisionEngine(risk, Allowlist(conn), config)


def _ev(kind, source=Layer.L2_ANOMALY, strength=0.8, weight=2.0, flow_id="1",
        ts="2026-11-01T10:00:00.000000Z", host=HOST, **kw):
    return Evidence(source=source, flow_id=flow_id, host_ip=host, kind=kind,
                    strength=strength, weight=weight, timestamp=ts, **kw)


def _anomaly(**kw):
    return _ev(EvidenceType.ANOMALY, **kw)


def _cls(label, conf, **kw):
    return _ev(EvidenceType.CLASS, source=Layer.L3_CLASSIFIER, strength=conf, weight=2.5,
               predicted_class=label, confidence=conf, **kw)


def test_allowlisted_source_passes_and_scores_nothing():
    d = _engine(["10.0.0.0/24"]).decide([_ev(EvidenceType.SIGNATURE, Layer.L1_SIGNATURE, 1.0, 3.0)])
    assert d.verdict.action == Action.PASS
    assert d.host_score is None


def test_hard_signature_blocks_on_layer_1():
    d = _engine().decide([_ev(EvidenceType.SIGNATURE, Layer.L1_SIGNATURE, 1.0, 3.0,
                              flow_id=None, signature_id=2024217)])
    assert d.verdict.action == Action.BLOCK
    assert d.verdict.layers == [Layer.L1_SIGNATURE]
    assert "2024217" in d.verdict.explanation
    assert d.host_score.score == 3.0


def test_arp_spoof_blocks_attributed_to_arp():
    d = _engine().decide([_ev(EvidenceType.SIGNATURE, Layer.ARP, 1.0, 3.0, flow_id=None)])
    assert d.verdict.action == Action.BLOCK
    assert d.verdict.layers == [Layer.ARP]


def test_soft_signature_alerts_only():
    d = _engine().decide([_ev(EvidenceType.SIGNATURE, Layer.L1_SIGNATURE, 0.5, 3.0)])
    assert d.verdict.action == Action.ALERT


def test_lone_anomaly_alerts_and_raises_host_score():
    d = _engine().decide([_anomaly()])
    assert d.verdict.action == Action.ALERT
    assert d.verdict.layers == [Layer.L2_ANOMALY]
    assert d.verdict.flow_id == "1"
    assert d.host_score.score == 2.0


def test_steady_trickle_of_alerts_blocks_at_threshold_then_resets():
    engine = _engine()
    first = engine.decide([_anomaly()])
    second = engine.decide([_anomaly()])
    third = engine.decide([_anomaly()])  # 2 + 2 + 2 = 6.0 = threshold
    assert [first.verdict.action, second.verdict.action] == [Action.ALERT, Action.ALERT]
    assert third.verdict.action == Action.BLOCK
    assert third.verdict.layers[0] == Layer.HOST
    assert third.host_score.score == 0.0
    assert engine.decide([_anomaly()]).host_score.score == 2.0


def test_alerts_spread_over_hours_never_accumulate_to_a_block():
    engine = _engine()
    for hour in range(8, 20):
        d = engine.decide([_anomaly(ts=f"2026-11-01T{hour:02d}:00:00.000000Z")])
        assert d.verdict.action == Action.ALERT


def test_exfil_and_beacon_count_toward_the_host_score():
    engine = _engine()
    engine.decide([_ev(EvidenceType.EXFIL, flow_id=None, strength=1.0)])
    d = engine.decide([_ev(EvidenceType.BEACON, flow_id=None, strength=1.0, weight=2.5)])
    assert d.verdict.action == Action.ALERT
    assert d.host_score.score == pytest.approx(4.5)


def test_confident_known_attack_blocks_on_layer_3_alone():
    d = _engine().decide([_cls("DDoS", 0.95)])
    assert d.verdict.action == Action.BLOCK
    assert d.verdict.layers == [Layer.L3_CLASSIFIER]
    assert d.verdict.attack_class == "DDoS"


def test_moderate_class_blocks_only_when_anomaly_agrees():
    alone = _engine().decide([_cls("PortScan", 0.75)])
    together = _engine().decide([_cls("PortScan", 0.75), _anomaly()])
    assert alone.verdict.action == Action.ALERT
    assert together.verdict.action == Action.BLOCK
    assert together.verdict.layers == [Layer.L2_ANOMALY, Layer.L3_CLASSIFIER]


def test_benign_and_low_confidence_classes_are_not_attacks():
    engine = _engine()
    assert engine.decide([_cls("Benign", 0.99)]).verdict.action == Action.PASS
    assert engine.decide([_cls("DDoS", 0.40)]).verdict.action == Action.PASS
    assert engine.decide([_cls("Unknown", 0.99)]).verdict.action == Action.PASS


def test_anomaly_with_benign_class_stays_an_alert():
    d = _engine().decide([_cls("Benign", 0.99), _anomaly()])
    assert d.verdict.action == Action.ALERT


def test_most_confident_class_wins():
    d = _engine().decide([_cls("PortScan", 0.60), _cls("DDoS", 0.95)])
    assert d.verdict.attack_class == "DDoS"
    assert d.verdict.action == Action.BLOCK


def test_hosts_are_scored_separately():
    engine = _engine()
    engine.decide([_anomaly(host="10.0.0.1")])
    engine.decide([_anomaly(host="10.0.0.1")])
    assert engine.decide([_anomaly(host="10.0.0.2")]).host_score.score == 2.0


def test_missing_source_address_passes():
    assert _engine().decide([_anomaly(host="")]).verdict.action == Action.PASS


def _disable(engine, key):
    from common import config_loader
    config_loader.update(engine._config._conn, key, False)
    engine._config._cache.clear()


def test_disabled_layer_evidence_is_ignored():
    engine = _engine()
    _disable(engine, "detection.layer1_enabled")
    d = engine.decide([_ev(EvidenceType.SIGNATURE, Layer.L1_SIGNATURE, 1.0, 3.0)])
    assert d.verdict.action == Action.PASS
    assert d.host_score is None
    arp = engine.decide([_ev(EvidenceType.SIGNATURE, Layer.ARP, 1.0, 3.0)])
    assert arp.verdict.action == Action.PASS


def test_disabling_one_layer_keeps_the_others_working():
    engine = _engine()
    _disable(engine, "detection.layer2_enabled")
    mixed = engine.decide([_anomaly(), _ev(EvidenceType.SIGNATURE, Layer.L1_SIGNATURE, 0.5, 3.0)])
    assert mixed.verdict.action == Action.ALERT
    assert mixed.verdict.layers == [Layer.L1_SIGNATURE]
    assert mixed.host_score.score == 3.0
