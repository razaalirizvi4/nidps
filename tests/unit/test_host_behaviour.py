import math

import pytest

from common.schemas import EvidenceType, Layer
from services.mlscorer.host_behaviour import (
    BeaconTracker,
    ExfiltrationTracker,
    FlowObservation,
    _ExfilBucket,
    _ExfilState,
)


def _obs(host_ip, dst_ip, fwd, bwd, end_time, is_partial=False, is_new_destination=False, sni=None, ja3=None):
    return FlowObservation(
        host_ip=host_ip, dst_ip=dst_ip, sni=sni, ja3=ja3, fwd_bytes=fwd, bwd_bytes=bwd,
        end_time_epoch=end_time, is_partial=is_partial, is_new_destination=is_new_destination,
    )


def test_first_bucket_finalize_has_no_baseline_and_never_flags():
    # alpha=0.5, bucket=60s, k_std=2.0, u_max disabled (fast path tested separately below).
    # idle_timeout_s=0 asserts observations arrive in end_time order, so no grace margin is
    # needed -- this reproduces legacy (pre-watermark) finalize timing exactly.
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    # Bucket 0 (t=10): fwd=100, bwd=100. Bucket 1 (t=70) finalizes bucket 0 -- but there is no
    # established baseline yet, so no check runs no matter how large bucket 0 was.
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 10_000.0, 1.0, end_time=10.0)) == []
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 1.0, 1.0, end_time=70.0)) == []


def test_bucket_flags_only_when_magnitude_and_ratio_both_hold():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    # Establish a baseline across three one-flow-per-bucket buckets (100, 120, 130 fwd bytes,
    # all with a near-1:1 ratio so the ratio gate alone would never fire for them):
    #   bucket0 fwd=100,bwd=100 -> finalized by bucket1's arrival: no baseline yet, skip check.
    #     baseline becomes mean=50.0, var=5000.0 (alpha*100^2 off a mean of 0).
    #   bucket1 fwd=120,bwd=110 -> finalized by bucket2's arrival: mean=50,var=5000,std=70.71...
    #     threshold=50+2*70.71=191.4; b_t=120 < threshold -> no flag. New mean=85.0, var=4950.0.
    #   bucket2 fwd=130,bwd=120 -> finalized by bucket3's arrival: mean=85,var=4950,std=70.36...
    #     threshold=85+2*70.36=225.7; b_t=130 < threshold -> no flag. New mean=107.5, var=3487.5.
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000, bwd=50 (ratio=100, far over EXFIL_RATIO_THRESHOLD). Not yet finalized --
    # no evidence from THIS call; it just starts accumulating bucket3.
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 5000.0, 50.0, end_time=190.0)) == []
    # bucket4 arrival finalizes bucket3: mean=107.5, var=3487.5, std=59.055...
    #   threshold=107.5+2*59.055=225.6; b_t=5000 > threshold AND ratio=5000/50=100 >= 3.0 -> FLAG.
    evidence = tracker.observe(_obs("10.0.0.5", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].source == Layer.L2_ANOMALY
    assert evidence[0].host_ip == "10.0.0.5"
    assert evidence[0].weight == 0.0
    assert evidence[0].strength == 1.0


def test_bucket_does_not_flag_when_ratio_is_too_low_despite_large_magnitude():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000 (huge, would trip the magnitude check) but bwd=4000 too -- ratio=1.25,
    # well under EXFIL_RATIO_THRESHOLD=3.0 -- this is "normal" large two-way traffic.
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 5000.0, 4000.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.9", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert evidence == []


def test_zero_backward_bytes_does_not_raise_and_ratio_is_treated_as_maximal():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000, bwd=0 exactly -- must not raise ZeroDivisionError.
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 5000.0, 0.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.3", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert len(evidence) == 1


def test_fast_path_fires_only_on_partial_segment_over_umax_to_new_destination():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000, idle_timeout_s=0)
    # Not partial -- no fast-path check regardless of size/destination.
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 5000.0, 10.0, end_time=10.0, is_partial=False, is_new_destination=True)) == []
    # Partial, over u_max, but NOT a new destination -- no fast-path evidence.
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 5000.0, 10.0, end_time=20.0, is_partial=True, is_new_destination=False)) == []
    # Partial, under u_max, new destination -- no fast-path evidence (not over the threshold).
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 500.0, 10.0, end_time=30.0, is_partial=True, is_new_destination=True)) == []
    # Partial, over u_max, new destination -- fires immediately, no bucket finalize needed.
    evidence = tracker.observe(_obs("10.0.0.7", "9.9.9.9", 5000.0, 10.0, end_time=40.0, is_partial=True, is_new_destination=True))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].strength == 1.0


def test_u_max_none_disables_fast_path_entirely():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    evidence = tracker.observe(_obs("10.0.0.8", "9.9.9.9", 1_000_000.0, 1.0, end_time=10.0, is_partial=True, is_new_destination=True))
    assert evidence == []


def test_set_u_max_updates_the_fast_path_threshold_in_place():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    # With u_max=None, the fast path stays disabled no matter how large the transfer is.
    evidence = tracker.observe(_obs("10.0.0.9", "9.9.9.9", 5000.0, 10.0, end_time=10.0, is_partial=True, is_new_destination=True))
    assert evidence == []

    tracker.set_u_max(1000)

    # Same shape of observation (partial, over the new u_max, new destination) now fires.
    evidence = tracker.observe(_obs("10.0.0.9", "8.8.8.8", 5000.0, 10.0, end_time=20.0, is_partial=True, is_new_destination=True))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].strength == 1.0


def test_group_below_min_connections_never_computes_cv_or_flags():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    for t in (0.0, 10.0, 20.0, 30.0):  # only 4 connections, below min_connections=5
        result = tracker.observe(_obs("10.0.0.5", "1.2.3.4", 100.0, 100.0, end_time=t, ja3="abc"))
    assert result is None


def test_zero_mean_interval_or_bytes_does_not_raise():
    tracker = BeaconTracker(min_connections=2, cv_threshold=0.15)
    # Two connections at the exact same timestamp -- mean inter-arrival would be 0.
    tracker.observe(_obs("10.0.0.6", "1.2.3.4", 0.0, 0.0, end_time=5.0, ja3="abc"))
    result = tracker.observe(_obs("10.0.0.6", "1.2.3.4", 0.0, 0.0, end_time=5.0, ja3="abc"))
    assert result is None  # must not raise ZeroDivisionError


def test_periodic_group_with_rare_ja3_and_low_byte_variance_is_flagged():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    # 5 connections, 60s apart exactly (CV_time = 0.0), each carrying ~100 bytes total
    # (fwd+bwd), varying by at most 1 byte (CV_bytes well under 0.15), same rare JA3.
    result = None
    sizes = [100.0, 99.0, 100.0, 101.0, 100.0]
    for i, size in enumerate(sizes):
        result = tracker.observe(
            _obs("10.0.0.5", "9.9.9.9", size / 2, size / 2, end_time=i * 60.0, ja3="rare-fingerprint")
        )
    assert result is not None
    assert result.kind.value == "BEACON"
    assert result.host_ip == "10.0.0.5"
    assert result.weight == 0.0


def test_common_ja3_used_by_many_hosts_is_never_flagged_even_if_perfectly_periodic():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    # A common JA3 (e.g. a mainstream browser) seen from 3 distinct hosts -- not rare.
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        tracker.observe(_obs(host, "9.9.9.9", 50.0, 50.0, end_time=0.0, ja3="common-browser"))
    result = None
    for i in range(5):
        result = tracker.observe(
            _obs("10.0.0.1", "9.9.9.9", 50.0, 50.0, end_time=i * 60.0, ja3="common-browser")
        )
    assert result is None


def test_irregular_human_driven_timing_is_never_flagged():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    irregular_times = [0.0, 12.0, 95.0, 97.0, 400.0]  # high-variance gaps
    result = None
    for t in irregular_times:
        result = tracker.observe(_obs("10.0.0.5", "9.9.9.9", 100.0, 0.0, end_time=t, ja3="rare-fingerprint"))
    assert result is None


from services.mlscorer.host_behaviour import HostBehaviourTracker


def test_host_behaviour_tracker_combines_both_trackers_results():
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000, idle_timeout_s=0)
    beacon = BeaconTracker(min_connections=2, cv_threshold=0.15)
    combined = HostBehaviourTracker(exfil=exfil, beacon=beacon)

    # A fast-path-triggering observation: partial, over u_max, new destination. BeaconTracker
    # will see only 1 connection in this group (below its min_connections=2), so it contributes
    # nothing -- the combined result should have exactly the 1 EXFIL item.
    result = combined.observe(_obs(
        "10.0.0.5", "9.9.9.9", 5000.0, 10.0, end_time=10.0,
        is_partial=True, is_new_destination=True, ja3="rare-fp",
    ))
    assert len(result) == 1
    assert result[0].kind.value == "EXFIL"


def test_host_behaviour_tracker_returns_empty_list_when_neither_tracker_flags():
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)
    beacon = BeaconTracker(min_connections=5, cv_threshold=0.15)
    combined = HostBehaviourTracker(exfil=exfil, beacon=beacon)
    assert combined.observe(_obs("10.0.0.5", "1.2.3.4", 10.0, 10.0, end_time=0.0)) == []


# --- Watermark-based bucket buffering (design: exfil-bucket-watermark-design.md) ---


def test_in_order_regression_with_grace_margin_matches_legacy_after_flush():
    # idle_timeout_s=30, bucket_seconds=60 -> L=90, G=2. One flow per bucket, arrivals already
    # in end_time order (no backward jumps) -- this checks the watermark only DELAYS
    # finalization, it never changes which totals get finalized, in what order, or whether
    # they flag.
    host = "10.0.0.5"
    times_and_values = [
        (10.0, 100.0, 100.0),
        (70.0, 120.0, 110.0),
        (130.0, 130.0, 120.0),
        (190.0, 5000.0, 50.0),
        (250.0, 10.0, 10.0),
        (310.0, 20.0, 20.0),
    ]

    graced = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=30)
    legacy = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=0)

    graced_evidence = []
    legacy_evidence = []
    for t, fwd, bwd in times_and_values:
        legacy_evidence += legacy.observe(_obs(host, "1.2.3.4", fwd, bwd, end_time=t))
        graced_evidence += graced.observe(_obs(host, "1.2.3.4", fwd, bwd, end_time=t))
        if t == 70.0:
            assert 0 in graced._state[host].open_buckets  # not yet finalized (cutoff=-1)
        if t == 130.0:
            assert 0 in graced._state[host].open_buckets  # cutoff=0; 0 is not < 0
        if t == 190.0:
            assert 0 not in graced._state[host].open_buckets  # cutoff=1 now; finalizes here

    # Drain whatever each tracker still has open. Legacy always has the newest bucket open
    # (it only finalizes on the next DIFFERING index); graced has the last couple of buckets
    # still inside the grace window open. flush_all() finalizes both in the same ascending
    # order, so afterwards both trackers have finalized buckets 0..5 in identical order.
    legacy_evidence += legacy.flush_all()
    graced_evidence += graced.flush_all()

    assert graced._state[host].ewma_mean == legacy._state[host].ewma_mean
    assert graced._state[host].ewma_var == legacy._state[host].ewma_var
    assert [e.kind for e in graced_evidence] == [e.kind for e in legacy_evidence]


def test_exfiltration_scenario_from_bug_report_sums_fragmented_heavy_flows_and_flags():
    # idle_timeout_s=30, bucket_seconds=60 (L=90). This is the regression test for the bug:
    # a real exfil window reported as several concurrent, out-of-order connections must be
    # summed into one bucket total and flagged, instead of being fragmented into several
    # unremarkable pieces that also corrupt the EWMA baseline (which is what the OLD
    # single-bucket-accumulator code did).
    host = "10.0.0.5"
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=30)

    # Baseline: three near-1:1 buckets (bucket indices 0, 1, 2).
    tracker.observe(_obs(host, "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs(host, "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs(host, "1.2.3.4", 130.0, 120.0, end_time=130.0))
    assert set(tracker._state[host].open_buckets) == {0, 1, 2}  # cutoff still <= 0 here

    # First heavy, one-sided flow lands in bucket 5 and advances the watermark enough
    # (E=305, cutoff=floor((305-90)/60)=3) to finalize buckets 0, 1, 2 -- establishing the
    # baseline -- with none of them flagging (same small, near-1:1 totals as the existing
    # baseline tests above).
    evidence = tracker.observe(_obs(host, "1.2.3.4", 5000.0, 10.0, end_time=305.0))
    assert evidence == []
    assert set(tracker._state[host].open_buckets) == {5}
    assert tracker._state[host].initialized is True

    # An unrelated expireIdle-style flow lands in bucket 3 -- behind the watermark, but still
    # inside the grace window (cutoff is still 3, and 3 is not < 3) -- so it must accumulate,
    # not drop.
    evidence = tracker.observe(_obs(host, "1.2.3.4", 50.0, 45.0, end_time=190.0))
    assert evidence == []
    assert set(tracker._state[host].open_buckets) == {3, 5}

    # Second heavy flow, same bucket 5 -- cutoff is still 3 (floor((315-90)/60)=3), so still
    # no finalize.
    evidence = tracker.observe(_obs(host, "1.2.3.4", 6000.0, 10.0, end_time=315.0))
    assert evidence == []
    assert set(tracker._state[host].open_buckets) == {3, 5}
    assert tracker._state[host].open_buckets[5].fwd == 5000.0 + 6000.0

    # Third heavy flow pushes the watermark enough (E=350, cutoff=4) to finalize bucket 3
    # (small, unrelated, no flag) while bucket 5 -- still below the new cutoff -- stays open,
    # now holding the SUM of all three heavy flows. Under the pre-watermark code these would
    # have been three separate fragments, each too small to ever flag.
    evidence = tracker.observe(_obs(host, "1.2.3.4", 4000.0, 10.0, end_time=350.0))
    assert evidence == []  # bucket 3's total (50 fwd) is far below threshold
    assert set(tracker._state[host].open_buckets) == {5}
    assert tracker._state[host].open_buckets[5].fwd == 5000.0 + 6000.0 + 4000.0
    assert tracker._state[host].open_buckets[5].bwd == 10.0 + 10.0 + 10.0

    # The watermark eventually passes bucket 5 (end_time=550 -> cutoff=7): the full summed
    # total trips the magnitude+ratio gate, which the individual fragments never would have.
    evidence = tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=550.0))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].host_ip == host


def test_out_of_order_arrivals_within_the_grace_window_accumulate_and_finalize_ascending():
    # idle_timeout_s=120, bucket_seconds=10 -> L=130, wide enough that none of these buckets
    # drain while the zig-zag is in progress.
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=10, k_std=2.0, u_max=None, idle_timeout_s=120)
    host = "10.0.0.1"

    # Feed bucket indices in the order 4, 3, 4, 5, 3 (end_time // 10 gives the bucket index).
    tracker.observe(_obs(host, "1.2.3.4", 40.0, 1.0, end_time=45.0))   # bucket 4
    tracker.observe(_obs(host, "1.2.3.4", 30.0, 1.0, end_time=35.0))   # bucket 3
    tracker.observe(_obs(host, "1.2.3.4", 41.0, 1.0, end_time=46.0))   # bucket 4 again
    tracker.observe(_obs(host, "1.2.3.4", 50.0, 1.0, end_time=55.0))   # bucket 5
    tracker.observe(_obs(host, "1.2.3.4", 31.0, 1.0, end_time=36.0))   # bucket 3 again

    assert set(tracker._state[host].open_buckets) == {3, 4, 5}
    assert tracker._state[host].open_buckets[3].fwd == 30.0 + 31.0
    assert tracker._state[host].open_buckets[4].fwd == 40.0 + 41.0
    assert tracker._state[host].open_buckets[5].fwd == 50.0

    finalize_order = []
    original_finalize = tracker._finalize_bucket

    def _recording_finalize(host_ip, state, bucket):
        finalize_order.append(bucket.fwd)
        return original_finalize(host_ip, state, bucket)

    tracker._finalize_bucket = _recording_finalize

    # Push the watermark far enough ahead to drain buckets 3, 4, and 5 in one call.
    tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=10000.0))

    assert finalize_order == [61.0, 81.0, 50.0]  # ascending bucket order: 3, then 4, then 5


def test_arrival_outside_grace_window_is_dropped_and_counted_but_fast_path_still_fires():
    # idle_timeout_s=10, bucket_seconds=10 -> L=20.
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=10, k_std=2.0, u_max=500, idle_timeout_s=10)
    host = "10.0.0.2"

    tracker.observe(_obs(host, "1.2.3.4", 10.0, 10.0, end_time=1000.0))  # bucket 100, cutoff -> 98
    mean_before = tracker._state[host].ewma_mean
    var_before = tracker._state[host].ewma_var
    open_before = dict(tracker._state[host].open_buckets)

    # Bucket 50 is far behind the cutoff (98) -- dropped, not accumulated.
    evidence = tracker.observe(_obs(host, "1.2.3.4", 999.0, 1.0, end_time=500.0))
    assert evidence == []
    assert tracker.dropped_late_observations == 1
    assert tracker._state[host].ewma_mean == mean_before
    assert tracker._state[host].ewma_var == var_before
    assert tracker._state[host].open_buckets == open_before

    # Same stale observation, but shaped to trip the fast path -- that check runs before the
    # late-arrival drop (STEP 1 before STEP 5), so it still fires even though the bucket half
    # of this same observation is dropped.
    evidence = tracker.observe(_obs(
        host, "1.2.3.4", 999.0, 1.0, end_time=500.0, is_partial=True, is_new_destination=True,
    ))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert tracker.dropped_late_observations == 2


def test_ordered_finalization_holds_across_a_backward_jump():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=10, k_std=2.0, u_max=None, idle_timeout_s=120)
    host = "10.0.0.3"
    finalize_order = []

    class _RecordingDict(dict):
        def pop(self, key, *a, **kw):
            finalize_order.append(key)
            return super().pop(key, *a, **kw)

    # Bootstrap the host's state, then swap in a dict subclass that records the order buckets
    # are popped (i.e. finalized) in.
    tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=0.0))
    state = tracker._state[host]
    state.open_buckets = _RecordingDict(state.open_buckets)

    # Zig-zag bucket indices: 5, 2, 5, 3, 2, 4. idle_timeout_s=120, bucket_seconds=10 ->
    # L=130, wide enough to keep everything open through this short zig-zag.
    for end_time in (55.0, 25.0, 56.0, 35.0, 26.0, 45.0):
        tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=end_time))

    # Force-drain everything by pushing the watermark far ahead.
    tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=100000.0))

    assert finalize_order == [0, 2, 3, 4, 5]  # strictly ascending despite the zig-zag arrival order


def test_cap_force_finalizes_lowest_index_when_exceeded():
    # idle_timeout_s=120, bucket_seconds=10 -> L=130, G=ceil(130/10)=13, cap=G+2=15.
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=10, k_std=2.0, u_max=None, idle_timeout_s=120)
    assert tracker._max_open_buckets == 15
    host = "10.0.0.4"

    tracker._state[host] = _ExfilState()
    state = tracker._state[host]
    for i in range(tracker._max_open_buckets + 1):  # cap + 1 = 16 entries
        state.open_buckets[i] = _ExfilBucket(fwd=float(i), bwd=1.0)

    # Pin the watermark so the normal drain (the cutoff) does not touch any seeded bucket --
    # only the hard cap (STEP 8) should fire.
    tracker._stream_max_end_time = 0.0

    tracker.observe(_obs(host, "1.2.3.4", 1.0, 1.0, end_time=0.0))

    assert len(state.open_buckets) == tracker._max_open_buckets
    assert 0 not in state.open_buckets  # the lowest seeded index was finalized first
    assert 1 in state.open_buckets


def test_single_bucket_host_never_finalizes_like_legacy():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=30)
    host = "10.0.0.6"
    for t in (10.0, 20.0, 30.0, 40.0):
        evidence = tracker.observe(_obs(host, "1.2.3.4", 100.0, 100.0, end_time=t))
        assert evidence == []
    state = tracker._state[host]
    assert state.ewma_mean == 0.0
    assert state.ewma_var == 0.0
    assert state.initialized is False
    assert set(state.open_buckets) == {0}


def test_global_watermark_closes_a_quiet_hosts_bucket_via_another_hosts_observe_call():
    # idle_timeout_s=30, bucket_seconds=60 -> L=90. This pins the all-host drain loop
    # (design doc Sec 4.2 / Sec 7 STEP 7): host A goes dark after filling some buckets, and
    # its buckets must still be finalized -- purely as a side effect of host B's observe()
    # calls advancing the global watermark -- with no further host A observation and no
    # flush_all() call anywhere in this test (that would exercise the backstop, not the
    # all-host drain this test is pinning).
    host_a, host_b = "10.0.0.30", "10.0.0.31"
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=30)

    # Host A: baseline (buckets 0, 1, 2), then a heavy one-sided flow in bucket 5 (end_time=305
    # advances the watermark enough -- cutoff=floor((305-90)/60)=3 -- to finalize 0, 1, 2 right
    # away, establishing the baseline with no flag). Then an unrelated expireIdle-style flow in
    # bucket 3 (end_time=190, behind the watermark but still >= the cutoff of 3, so it
    # accumulates instead of dropping). Host A ends this block with buckets 3 and 5 both open.
    tracker.observe(_obs(host_a, "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs(host_a, "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs(host_a, "1.2.3.4", 130.0, 120.0, end_time=130.0))
    ev = tracker.observe(_obs(host_a, "1.2.3.4", 5000.0, 10.0, end_time=305.0))
    assert ev == []
    ev = tracker.observe(_obs(host_a, "1.2.3.4", 50.0, 45.0, end_time=190.0))
    assert ev == []
    assert set(tracker._state[host_a].open_buckets) == {3, 5}
    assert tracker._state[host_a].initialized is True
    mean_before = tracker._state[host_a].ewma_mean

    # Host A goes dark: no further observe() call for host A anywhere in this test.

    # Record finalize order (across all hosts) from here on, to confirm host A's own
    # ascending-order guarantee (requirement 4) holds even though host A itself never calls
    # observe() again -- the finalize calls below are all driven by host B's traffic.
    finalize_calls = []
    original_finalize = tracker._finalize_bucket

    def _recording_finalize(host_ip, state, bucket):
        finalize_calls.append((host_ip, bucket.fwd))
        return original_finalize(host_ip, state, bucket)

    tracker._finalize_bucket = _recording_finalize

    # Host B, call 1: end_time=400 -> watermark=400, cutoff=floor((400-90)/60)=5. This passes
    # host A's bucket 3 (3 < 5) but not yet bucket 5 (5 is not < 5): bucket 3 finalizes here,
    # with no flag (small, unrelated totals), purely from host B's call.
    ev = tracker.observe(_obs(host_b, "9.9.9.9", 10.0, 10.0, end_time=400.0))
    assert ev == []
    assert set(tracker._state[host_a].open_buckets) == {5}  # bucket 3 closed, 5 still open

    # Host B, call 2: end_time=460 -> watermark=460, cutoff=floor((460-90)/60)=6. Now host A's
    # bucket 5 (5 < 6) finalizes too -- and its summed heavy, one-sided total trips the
    # magnitude+ratio gate. The returned Evidence's host_ip is host A's, even though this
    # call's own obs.host_ip is host B.
    evidence = tracker.observe(_obs(host_b, "9.9.9.9", 10.0, 10.0, end_time=460.0))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].host_ip == host_a
    assert tracker._state[host_a].open_buckets == {}

    # Host B, call 3: end_time=520 -> watermark=520, cutoff=floor((520-90)/60)=7. Host A has
    # nothing left to finalize; this call only drains host B's own earlier bucket, confirming
    # the all-host loop does not disturb a host with no open buckets.
    ev = tracker.observe(_obs(host_b, "9.9.9.9", 1.0, 1.0, end_time=520.0))
    assert all(e.host_ip != host_a for e in ev)

    # Host A's own finalize order was strictly ascending (bucket 3 then bucket 5), and both
    # finalizations were driven entirely by host B's calls.
    host_a_finalizes = [(h, fwd) for h, fwd in finalize_calls if h == host_a]
    assert host_a_finalizes == [(host_a, 50.0), (host_a, 5000.0)]
    assert tracker._state[host_a].ewma_mean != mean_before  # baseline moved with no host-A call


def test_flush_all_finalizes_every_open_bucket_for_every_host_then_is_idempotent():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None, idle_timeout_s=30)
    host_a, host_b = "10.0.0.9", "10.0.0.10"

    tracker.observe(_obs(host_a, "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs(host_a, "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs(host_a, "1.2.3.4", 130.0, 120.0, end_time=130.0))
    assert set(tracker._state[host_a].open_buckets) == {0, 1, 2}

    # A heavy one-sided bucket, which also advances the watermark enough to finalize bucket 0
    # right away (no baseline yet, so no flag from that finalize).
    ev = tracker.observe(_obs(host_a, "1.2.3.4", 5000.0, 10.0, end_time=190.0))
    assert ev == []
    assert set(tracker._state[host_a].open_buckets) == {1, 2, 3}

    # Host B: a single open bucket, no baseline established yet. end_time=100.0 (bucket 1) is
    # used rather than something in bucket 0 -- the global watermark is already 190.0 at this
    # point (from host A's traffic above), so a bucket-0 observation for host B would be
    # immediately finalized within this very call (its own index is already behind the
    # shared cutoff); bucket 1 is not, and stays open for flush_all() to pick up below.
    tracker.observe(_obs(host_b, "9.9.9.9", 10.0, 10.0, end_time=100.0))
    assert set(tracker._state[host_b].open_buckets) == {1}

    watermark_before = tracker._stream_max_end_time
    evidence = tracker.flush_all()

    # Only host A's heavy bucket (index 3) trips the gate; buckets 1 and 2 are the same
    # small, non-flagging baseline totals used throughout this file.
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].host_ip == host_a

    assert tracker._state[host_a].open_buckets == {}
    assert tracker._state[host_b].open_buckets == {}
    assert tracker._state[host_a].initialized is True
    assert tracker._state[host_b].initialized is True
    assert tracker._stream_max_end_time == watermark_before  # unchanged by flush_all()

    assert tracker.flush_all() == []  # idempotent


def test_constructor_requires_idle_timeout_s():
    with pytest.raises(TypeError):
        ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
