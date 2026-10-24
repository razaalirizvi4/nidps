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
