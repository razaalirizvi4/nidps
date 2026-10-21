import random

from training.selfcollected.attacks.c2_beacon import jitter_intervals, run


def test_jitter_intervals_stays_within_expected_bounds():
    rng = random.Random(42)
    intervals = jitter_intervals(base_interval=10.0, jitter_fraction=0.2, count=50, rng=rng)
    assert len(intervals) == 50
    for interval in intervals:
        assert 8.0 <= interval <= 12.0  # 10 +/- 20%


def test_jitter_intervals_is_reproducible_with_same_seed():
    rng1 = random.Random(7)
    rng2 = random.Random(7)
    assert jitter_intervals(5.0, 0.1, 10, rng1) == jitter_intervals(5.0, 0.1, 10, rng2)


def test_run_dry_run_sends_no_beacons(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.c2_beacon.connect",
        lambda host, port: called.append((host, port)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"


def test_run_sends_count_beacons(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.c2_beacon.connect",
        lambda host, port: called.append((host, port)) or "TLSv1.3",
    )
    monkeypatch.setattr("time.sleep", lambda s: None)  # don't actually wait in tests
    record = run("10.0.0.3", "10.0.0.2", tmp_path, count=3)
    assert len(called) == 3
    assert record.params["beacons_sent"] == 3
