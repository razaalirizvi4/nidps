from common.schemas import EvidenceType, Layer
from services.sigbridge.signature_detector import SignatureDetector, severity_to_strength


def test_severity_to_strength_drop_or_severity1_is_max():
    assert severity_to_strength(severity=2, action="drop") == 1.0
    assert severity_to_strength(severity=1, action="allowed") == 1.0


def test_severity_to_strength_scales_down_for_lower_severity():
    assert severity_to_strength(severity=2, action="allowed") == 0.6
    assert severity_to_strength(severity=3, action="allowed") == 0.3
    assert severity_to_strength(severity=None, action="allowed") == 0.25


def test_ingest_eve_alert_builds_evidence():
    detector = SignatureDetector()
    alert = {
        "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 2001219, "severity": 2, "action": "allowed"},
    }
    evidence = detector.ingestEveAlert(alert)

    assert evidence.source == Layer.L1_SIGNATURE
    assert evidence.kind == EvidenceType.SIGNATURE
    assert evidence.host_ip == "10.0.0.5"
    assert evidence.flow_id is None
    assert evidence.strength == 0.6
    assert evidence.signature_id == 2001219


def test_analyse_wraps_single_evidence_in_list():
    detector = SignatureDetector()
    alert = {"src_ip": "10.0.0.5", "alert": {"signature_id": 1, "severity": 1, "action": "drop"}}
    result = detector.analyse(alert)
    assert len(result) == 1
    assert result[0].strength == 1.0
