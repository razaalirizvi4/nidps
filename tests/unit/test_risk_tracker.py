import pytest

from services.decision.risk_tracker import RiskScoreTracker

T0 = "2026-11-01T10:00:00.000000Z"
T1 = "2026-11-01T10:10:00.000000Z"  # 600 s later
T2 = "2026-11-01T10:20:00.000000Z"


def _tracker():
    return RiskScoreTracker(half_life_s=lambda: 600)


def test_first_add_is_just_the_weight():
    assert _tracker().add("10.0.0.5", 2.0, T0) == 2.0


def test_score_halves_after_one_half_life_then_adds_weight():
    t = _tracker()
    t.add("10.0.0.5", 4.0, T0)
    assert t.add("10.0.0.5", 1.0, T1) == pytest.approx(3.0)


def test_current_decays_without_changing_state():
    t = _tracker()
    t.add("10.0.0.5", 4.0, T0)
    assert t.current("10.0.0.5", T1) == pytest.approx(2.0)
    assert t.current("10.0.0.5", T2) == pytest.approx(1.0)
    assert t.current("unseen", T0) == 0.0


def test_hosts_are_independent():
    t = _tracker()
    t.add("a", 3.0, T0)
    assert t.add("b", 1.0, T0) == 1.0


def test_out_of_order_timestamp_does_not_grow_score():
    t = _tracker()
    t.add("a", 2.0, T1)
    assert t.add("a", 1.0, T0) == pytest.approx(3.0)


def test_half_life_is_read_each_call():
    half_life = {"v": 600}
    t = RiskScoreTracker(half_life_s=lambda: half_life["v"])
    t.add("a", 4.0, T0)
    half_life["v"] = 1200
    assert t.current("a", T1) == pytest.approx(4.0 * 2 ** -0.5)


def test_reset_clears_host():
    t = _tracker()
    t.add("a", 5.0, T0)
    t.reset("a")
    assert t.current("a", T0) == 0.0


def test_snapshot_reports_decayed_zero_once_then_forgets():
    t = _tracker()
    t.add("a", 1.0, T0)
    assert t.snapshot(T1)["a"] == pytest.approx(0.5)
    far = "2026-11-02T10:00:00.000000Z"
    assert t.snapshot(far) == {"a": 0.0}
    assert t.snapshot(far) == {}
