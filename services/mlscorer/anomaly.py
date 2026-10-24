"""Eq 5.2-5.3, FR-4.1-4.4: Isolation Forest anomaly scoring. _score_to_paper_convention() is the
one place sklearn's sign flip is undone -- score_samples() is documented by scikit-learn as "the
opposite of the anomaly score defined in the original paper" (the same paper Eq 5.2-5.3 comes
from), so s(x,psi) = -score_samples(x), clipped to [0,1] to guard floating-point edge cases."""
from __future__ import annotations

from typing import Optional

from sklearn.ensemble import IsolationForest

from common.detector import Detector
from common.schemas import (
    ComponentHealth,
    Evidence,
    EvidenceType,
    FEATURE_COUNT,
    FlowFeatures,
    HealthState,
    Layer,
    SCHEMA_VERSION,
    utc_now_iso,
)
from services.mlscorer.calibration import CalibrationState


class FeatureSchemaMismatch(ValueError):
    pass


def _score_to_paper_convention(model: IsolationForest, values: list) -> float:
    raw = model.score_samples([values])[0]
    return max(0.0, min(1.0, -raw))


def fit_bootstrap_model(
    X, n_estimators: int = 100, max_samples: int = 256, random_state: int = 42
) -> IsolationForest:
    """Fits a local IsolationForest on sample data for tests/bootstrapping. Production model
    loading goes through load_active_model() once the (separate, later) training phase exists."""
    return IsolationForest(
        n_estimators=n_estimators, max_samples=max_samples, random_state=random_state
    ).fit(X)


def load_active_model(conn, models_dir: str = ""):
    import joblib

    row = conn.execute(
        """SELECT model_id, file_path FROM model_package
           WHERE model_type = 'IFOREST' AND is_active = 1
           ORDER BY deployed_at DESC LIMIT 1"""
    ).fetchone()
    if row is None:
        raise LookupError("no active IFOREST model_package row found")
    model_id, file_path = row
    return model_id, joblib.load(file_path)


class AnomalyDetector(Detector):
    name = "mlscorer-anomaly"

    def __init__(
        self, model: IsolationForest, calibration: CalibrationState, model_id: Optional[int] = None
    ) -> None:
        self.model = model
        self.calibration = calibration
        self.model_id = model_id

    def score(self, features: FlowFeatures) -> float:
        if not features.validate():
            raise FeatureSchemaMismatch(
                f"expected {FEATURE_COUNT} floats under schema {SCHEMA_VERSION!r}, got "
                f"{len(features.values)} under {features.schema_version!r}"
            )
        return _score_to_paper_convention(self.model, features.values)

    def analyse(self, item) -> Optional[list]:
        host_ip, flow_id, features = item
        try:
            score = self.score(features)
        except FeatureSchemaMismatch:
            return None
        if score <= self.calibration.threshold:
            return None
        return [
            Evidence(
                source=Layer.L2_ANOMALY,
                flow_id=flow_id,
                host_ip=host_ip,
                kind=EvidenceType.ANOMALY,
                strength=score,
                weight=0.0,  # services/mlscorer/anomaly_service.py fills this from risk.weight_anomaly
                model_id=self.model_id,
            )
        ]

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
