import math

from common.schemas import EvidenceType, Layer
from services.mlscorer.host_behaviour import BeaconTracker, ExfiltrationTracker, FlowObservation


def _obs(host_ip, dst_ip, fwd, bwd, end_time, is_partial=False, is_new_destination=False, sni=None, ja3=None):
    return FlowObservation(
        host_ip=host_ip, dst_ip=dst_ip, sni=sni, ja3=ja3, fwd_bytes=fwd, bwd_bytes=bwd,
        end_time_epoch=end_time, is_partial=is_partial, is_new_destination=is_new_destination,
    )


def test_first_bucket_finalize_has_no_baseline_and_never_flags():
    # alpha=0.5, bucket=60s, k_std=2.0, u_max disabled (fast path tested separately below).
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    # Bucket 0 (t=10): fwd=100, bwd=100. Bucket 1 (t=70) finalizes bucket 0 -- but there is no
    # established baseline yet, so no check runs no matter how large bucket 0 was.
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 10_000.0, 1.0, end_time=10.0)) == []
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 1.0, 1.0, end_time=70.0)) == []


def test_bucket_flags_only_when_magnitude_and_ratio_both_hold():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
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
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000 (huge, would trip the magnitude check) but bwd=4000 too -- ratio=1.25,
    # well under EXFIL_RATIO_THRESHOLD=3.0 -- this is "normal" large two-way traffic.
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 5000.0, 4000.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.9", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert evidence == []


def test_zero_backward_bytes_does_not_raise_and_ratio_is_treated_as_maximal():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000, bwd=0 exactly -- must not raise ZeroDivisionError.
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 5000.0, 0.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.3", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert len(evidence) == 1


def test_fast_path_fires_only_on_partial_segment_over_umax_to_new_destination():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000)
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
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    evidence = tracker.observe(_obs("10.0.0.8", "9.9.9.9", 1_000_000.0, 1.0, end_time=10.0, is_partial=True, is_new_destination=True))
    assert evidence == []


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
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000)
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
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    beacon = BeaconTracker(min_connections=5, cv_threshold=0.15)
    combined = HostBehaviourTracker(exfil=exfil, beacon=beacon)
    assert combined.observe(_obs("10.0.0.5", "1.2.3.4", 10.0, 10.0, end_time=0.0)) == []
