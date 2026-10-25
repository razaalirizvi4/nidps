from common.schemas import EvidenceType, HealthState, Layer
from services.arpmon.arp_monitor import ArpFrame, ArpMonitor


def _frame(ip, mac, t=0.0, is_reply=True, is_gratuitous=False):
    return ArpFrame(sender_ip=ip, sender_mac=mac, is_reply=is_reply, is_gratuitous=is_gratuitous, timestamp=t)


def test_request_frames_are_ignored():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    frame = _frame("10.10.0.5", "bb:bb:bb:bb:bb:bb", is_reply=False, is_gratuitous=False)
    assert monitor.onArp(frame) == []


def test_bound_ip_with_mismatched_mac_raises_spoof_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    monitor.refreshBindings({"10.10.0.5": "cc:cc:cc:cc:cc:cc"})

    evidence = monitor.onArp(_frame("10.10.0.5", "bb:bb:bb:bb:bb:bb"))

    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.SIGNATURE
    assert evidence[0].source == Layer.ARP
    assert evidence[0].signature_id == 1
    assert evidence[0].host_ip == "10.10.0.5"


def test_matching_binding_raises_no_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    monitor.refreshBindings({"10.10.0.5": "bb:bb:bb:bb:bb:bb"})

    assert monitor.onArp(_frame("10.10.0.5", "BB:BB:BB:BB:BB:BB")) == []


def test_gateway_impersonation_raises_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")

    evidence = monitor.onArp(_frame("10.10.0.1", "ff:ff:ff:ff:ff:ff"))

    assert len(evidence) == 1
    assert evidence[0].signature_id == 2


def test_flood_raises_evidence_after_threshold():
    monitor = ArpMonitor(
        gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa", flood_threshold_n=3, flood_window_s=10.0
    )
    results = [
        monitor.onArp(_frame("10.10.0.5", "bb:bb:bb:bb:bb:bb", t=float(i))) for i in range(4)
    ]
    assert results[0] == results[1] == results[2] == []
    assert len(results[3]) == 1
    assert results[3][0].signature_id == 3


def test_analyse_wraps_onarp_for_detector_interface():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    result = monitor.analyse(_frame("10.10.0.1", "ff:ff:ff:ff:ff:ff"))
    assert result[0].signature_id == 2
    assert monitor.analyse(_frame("10.10.0.9", "bb:bb:bb:bb:bb:bb")) is None


def test_heartbeat_reports_normal():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    assert monitor.heartbeat().state == HealthState.NORMAL


def test_periodic_cleanup_drops_stale_empty_mac_histories():
    monitor = ArpMonitor(
        gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa", flood_threshold_n=1000, flood_window_s=5.0
    )
    stale_mac = "bb:bb:bb:bb:bb:bb"
    monitor.onArp(_frame("10.10.0.5", stale_mac, t=0.0))
    assert stale_mac in monitor._reply_times

    # 99 more onArp() calls (reaching the cleanup counter's threshold of 100) with a different
    # MAC, all far enough past t=0 that stale_mac's one-and-only entry has aged out of the
    # flood window by the time the periodic sweep runs.
    for i in range(99):
        monitor.onArp(_frame("10.10.0.9", "cc:cc:cc:cc:cc:cc", t=100.0 + i))

    assert stale_mac not in monitor._reply_times  # swept away, not retained forever
    assert "cc:cc:cc:cc:cc:cc" in monitor._reply_times  # recently active MAC is kept


def test_mac_randomized_storm_trips_global_flood_check_despite_no_single_mac_crossing_threshold():
    monitor = ArpMonitor(
        gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa", flood_threshold_n=5, flood_window_s=100.0
    )
    all_evidence = []
    for i in range(26):
        mac = f"aa:bb:cc:dd:ee:{i:02x}"  # a different (randomized) MAC every time
        all_evidence.extend(monitor.onArp(_frame("10.10.0.5", mac, t=float(i))))

    # No single MAC ever appears more than once, so the per-MAC check (threshold_n=5) never
    # fires -- but the global fallback (threshold_n * 5 = 25) must still catch the storm.
    assert any(ev.signature_id == 3 for ev in all_evidence)
