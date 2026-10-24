import statistics
import time

import numpy as np
import pytest

from common.schemas import FEATURE_COUNT, HealthState, FlowFeatures, SCHEMA_VERSION
from services.mlscorer.anomaly import AnomalyDetector, FeatureSchemaMismatch, fit_bootstrap_model
from services.mlscorer.calibration import CalibrationState


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


def test_score_meets_nfr3_median_latency_budget():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[1.0] * FEATURE_COUNT)

    durations_ms = []
    for _ in range(200):
        start = time.perf_counter()
        detector.score(features)
        durations_ms.append((time.perf_counter() - start) * 1000.0)

    assert statistics.median(durations_ms) <= 10.0
