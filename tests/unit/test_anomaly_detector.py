import json
import statistics
import time

import numpy as np
import pytest

from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import FEATURE_COUNT, HealthState, FlowFeatures, SCHEMA_VERSION
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.persistence import upsert_host
from services.mlscorer.anomaly import AnomalyDetector, FeatureSchemaMismatch, fit_bootstrap_model
from services.mlscorer.calibration import CalibrationState, recalibrate_if_due


def _fitted_model():
    rng = np.random.RandomState(42)
    X = rng.normal(0, 1, (100, FEATURE_COUNT))
    return fit_bootstrap_model(X, n_estimators=50, max_samples=64, random_state=42)


def _calibration(threshold: float) -> CalibrationState:
    return CalibrationState(threshold=threshold, global_threshold=threshold, computed_at="x", sample_count=0)


def test_score_is_bounded_and_higher_for_outliers():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))

    normal = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)
    outlier = FlowFeatures(schema_version=SCHEMA_VERSION, values=[50.0] * FEATURE_COUNT)

    normal_score = detector.score(normal)
    outlier_score = detector.score(outlier)

    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= outlier_score <= 1.0
    assert outlier_score > normal_score


def test_score_raises_on_wrong_length_feature_vector():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    bad = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * 10)

    with pytest.raises(FeatureSchemaMismatch):
        detector.score(bad)


def test_analyse_returns_none_below_threshold_and_evidence_above():
    calibration = _calibration(0.99)
    detector = AnomalyDetector(model=_fitted_model(), calibration=calibration, model_id=7)
    normal = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)

    assert detector.analyse(("10.0.0.5", "1", normal)) is None

    calibration.threshold = 0.0
    result = detector.analyse(("10.0.0.5", "1", normal))
    assert len(result) == 1
    assert result[0].kind.value == "ANOMALY"
    assert result[0].model_id == 7
    assert result[0].host_ip == "10.0.0.5"


def test_heartbeat_reports_normal():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    assert detector.heartbeat().state == HealthState.NORMAL


def test_score_accepted_directly_as_recalibrate_if_due_score_fn():
    # The plan's Task 17 docs say a future anomaly_service.py passes AnomalyDetector.score
    # directly as recalibrate_if_due's score_fn -- score_fn is called with a plain list[float]
    # read from flow_record.features JSON, not a FlowFeatures object (I3).
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))

    conn = connect(":memory:")
    seed_defaults(conn)
    conn.execute(
        "UPDATE config_setting SET value = '1' WHERE setting_key = 'anomaly.calibration_min_samples'"
    )
    conn.commit()
    model_id = conn.execute(
        """INSERT INTO model_package (model_type, version, file_path, feature_list_hash,
               extractor_version, is_active)
           VALUES ('IFOREST', 'dev', 'dev', 'dev', 'dev', 1)"""
    ).lastrowid
    conn.commit()
    host_id = upsert_host(conn, "10.0.0.5")

    values = [0.0] * len(FEATURE_NAMES)
    conn.execute(
        """INSERT INTO flow_record (host_id, src_ip, dst_ip, src_port, dst_port, protocol,
               start_time, end_time, segment_no, features, extractor_version)
           VALUES (?, '10.0.0.5', '1.2.3.4', 1, 2, 'TCP', '2026-01-05T00:00:00.000000Z',
                   '2026-01-05T00:00:00.000000Z', 0, ?, 'dev')""",
        (host_id, json.dumps(values)),
    )
    conn.commit()

    current_state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )

    new_state = recalibrate_if_due(
        conn, detector.score, model_id, current_state,
        window_start_iso="2026-01-01T00:00:00.000000Z", window_end_iso="2026-01-10T00:00:00.000000Z",
        now_iso="2026-01-10T00:00:00.000000Z",
    )

    assert isinstance(new_state, CalibrationState)
    assert new_state.sample_count == 1


def test_score_meets_nfr3_median_latency_budget():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[1.0] * FEATURE_COUNT)

    durations_ms = []
    for _ in range(200):
        start = time.perf_counter()
        detector.score(features)
        durations_ms.append((time.perf_counter() - start) * 1000.0)

    assert statistics.median(durations_ms) <= 10.0
