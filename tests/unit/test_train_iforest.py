import json

import joblib
import numpy as np
import pytest

from common.config_loader import seed_defaults
from common.db.migrate import connect
from models.compatibility import check_model_package
from models.registry import ModelRegistry
from services.flowextract.features import FEATURE_NAMES
from services.mlscorer.anomaly import AnomalyDetector, load_active_model
from services.mlscorer.calibration import load_calibration_state
from training.train_iforest import load_feature_sets, run_training, score_matrix


def _benign(n, seed=0):
    """Synthetic 'normal' flows: modest sizes, short durations, web ports."""
    rng = np.random.default_rng(seed)
    X = np.zeros((n, len(FEATURE_NAMES)))
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
    X[:, idx["duration_s"]] = rng.gamma(2.0, 1.0, n)
    X[:, idx["total_fwd_packets"]] = rng.integers(3, 30, n)
    X[:, idx["total_bwd_packets"]] = rng.integers(3, 40, n)
    X[:, idx["total_fwd_bytes"]] = rng.normal(2000, 500, n).clip(100)
    X[:, idx["total_bwd_bytes"]] = rng.normal(15000, 4000, n).clip(100)
    X[:, idx["pkt_len_mean"]] = rng.normal(500, 80, n).clip(40)
    X[:, idx["dst_port_numeric"]] = rng.choice([80, 443, 53], n)
    X[:, idx["protocol_tcp"]] = 1.0
    return X


def _attack(n, seed=1):
    """A flood: huge packet counts, tiny packets, very high rate, odd port."""
    rng = np.random.default_rng(seed)
    X = np.zeros((n, len(FEATURE_NAMES)))
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
    X[:, idx["duration_s"]] = rng.uniform(0.5, 3, n)
    X[:, idx["total_fwd_packets"]] = rng.integers(5000, 9000, n)
    X[:, idx["total_fwd_bytes"]] = rng.normal(300000, 20000, n)
    X[:, idx["pkt_len_mean"]] = 40.0
    X[:, idx["flow_packets_per_s"]] = rng.normal(5000, 500, n)
    X[:, idx["dst_port_numeric"]] = 31337
    X[:, idx["protocol_tcp"]] = 1.0
    return X


def _conn():
    conn = connect(":memory:")
    seed_defaults(conn)
    return conn


def test_training_registers_a_loadable_compatible_model(tmp_path):
    conn = _conn()
    mid = run_training(conn, _benign(2000), tmp_path, version="t1", n_estimators=30, activate=True)

    check_model_package(conn, mid)  # feature hash and extractor version match
    loaded_id, model = load_active_model(conn)
    assert loaded_id == mid
    assert (tmp_path / "iforest-t1.joblib").exists()
    row = conn.execute("SELECT metrics, training_data FROM model_package WHERE model_id=?", (mid,)).fetchone()
    assert json.loads(row[0])["train_flows"] == 1600
    assert json.loads(row[1])["benign_only"] is True


def test_attacks_score_above_the_global_threshold_and_benign_mostly_below(tmp_path):
    conn = _conn()
    mid = run_training(conn, _benign(3000), tmp_path, version="t1", n_estimators=50, activate=True)
    _, model = load_active_model(conn)
    tau = load_calibration_state(conn, mid).global_threshold

    benign_scores = score_matrix(model, _benign(1000, seed=7))
    attack_scores = score_matrix(model, _attack(200))
    assert (benign_scores > tau).mean() < 0.03  # close to the 0.5% target, allowing for noise
    assert (attack_scores > tau).mean() > 0.95


def test_detector_uses_the_trained_model_and_calibration(tmp_path):
    conn = _conn()
    mid = run_training(conn, _benign(2000), tmp_path, version="t1", n_estimators=30, activate=True)
    _, model = load_active_model(conn)
    detector = AnomalyDetector(model, load_calibration_state(conn, mid), model_id=mid)

    assert detector.analyse(("10.0.0.5", 1, _flowfeatures(_benign(1, seed=3)[0]))) is None
    evidence = detector.analyse(("10.0.0.5", 2, _flowfeatures(_attack(1)[0])))
    assert evidence and evidence[0].strength > detector.calibration.threshold


def _flowfeatures(row):
    from common.schemas import FlowFeatures, SCHEMA_VERSION
    return FlowFeatures(schema_version=SCHEMA_VERSION, values=[float(v) for v in row])


def test_initial_calibration_state_is_stored_with_u_max(tmp_path):
    conn = _conn()
    mid = run_training(conn, _benign(2000), tmp_path, version="t1", n_estimators=30)
    state = load_calibration_state(conn, mid)
    assert 0.3 < state.global_threshold < 1.0
    assert state.threshold == state.global_threshold
    assert state.u_max and state.u_max > 1000


def test_training_does_not_activate_unless_asked(tmp_path):
    conn = _conn()
    run_training(conn, _benign(500), tmp_path, version="t1", n_estimators=10)
    assert ModelRegistry(conn).active_id("IFOREST") is None


def test_defaults_come_from_config(tmp_path):
    conn = _conn()
    mid = run_training(conn, _benign(800), tmp_path, version="t1")
    metrics = json.loads(conn.execute("SELECT metrics FROM model_package WHERE model_id=?", (mid,)).fetchone()[0])
    assert (metrics["n_estimators"], metrics["max_samples"], metrics["calibration_percentile"]) == (100, 256, 99.5)


def test_too_little_data_is_refused(tmp_path):
    with pytest.raises(ValueError):
        run_training(_conn(), _benign(20), tmp_path)


def test_feature_sets_are_stacked_and_capped_per_set(tmp_path):
    for name, n in (("a", 300), ("b", 50)):
        d = tmp_path / name
        d.mkdir()
        np.savez_compressed(d / "features.npz", X=_benign(n), feature_names=np.array(FEATURE_NAMES))
    X, used = load_feature_sets([tmp_path / "a", tmp_path / "b"], max_per_set=100)
    assert len(X) == 150
    assert [u["flows"] for u in used] == [100, 50]


def test_feature_set_with_different_columns_is_rejected(tmp_path):
    np.savez_compressed(tmp_path / "features.npz", X=np.zeros((5, 3)), feature_names=np.array(["a", "b", "c"]))
    with pytest.raises(ValueError):
        load_feature_sets([tmp_path])
