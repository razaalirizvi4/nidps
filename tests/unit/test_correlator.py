from common.schemas import Evidence, EvidenceType, Layer
from services.decision.correlator import EvidenceCorrelator


def _ev(kind=EvidenceType.ANOMALY, flow_id="7", strength=0.8, source=Layer.L2_ANOMALY):
    return Evidence(source=source, flow_id=flow_id, host_ip="10.0.0.5", kind=kind,
                    strength=strength, weight=2.0)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_flowless_evidence_is_released_immediately():
    c = EvidenceCorrelator(clock=Clock())
    ev = _ev(flow_id=None, kind=EvidenceType.EXFIL)
    assert c.add(ev) == [[ev]]


def test_flow_evidence_waits_for_window_and_groups_by_flow():
    clock = Clock()
    c = EvidenceCorrelator(window_s=3.0, clock=clock)
    a, b = _ev(), _ev(kind=EvidenceType.CLASS, source=Layer.L3_CLASSIFIER)
    assert c.add(a) == []
    clock.t = 1.0
    assert c.add(b) == []
    clock.t = 2.9
    assert c.flush_due() == []
    clock.t = 3.0
    assert c.flush_due() == [[a, b]]
    assert c.flush_due() == []


def test_int_and_str_flow_ids_land_in_the_same_group():
    clock = Clock()
    c = EvidenceCorrelator(window_s=1.0, clock=clock)
    c.add(_ev(flow_id=7))
    c.add(_ev(flow_id="7"))
    clock.t = 1.0
    assert len(c.flush_due()[0]) == 2


def test_hard_signature_releases_pending_group_at_once():
    c = EvidenceCorrelator(clock=Clock())
    a = _ev()
    sig = _ev(kind=EvidenceType.SIGNATURE, strength=1.0, source=Layer.L1_SIGNATURE)
    c.add(a)
    assert c.add(sig) == [[a, sig]]
    assert c.flush_all() == []


def test_soft_signature_does_not_skip_the_window():
    c = EvidenceCorrelator(clock=Clock())
    assert c.add(_ev(kind=EvidenceType.SIGNATURE, strength=0.5, source=Layer.L1_SIGNATURE)) == []


def test_flush_all_drains_everything():
    c = EvidenceCorrelator(clock=Clock())
    c.add(_ev(flow_id="1"))
    c.add(_ev(flow_id="2"))
    assert len(c.flush_all()) == 2
