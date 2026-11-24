import numpy as np

from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.flowextract.features import FEATURE_NAMES
from training.evaluate_iforest import evaluate, load_flow_meta, top_flagged
from training.train_iforest import run_training
from tests.unit.test_train_iforest import _attack, _benign


def _write_set(path, X, dst="93.184.216.34", port="443"):
    path.mkdir()
    np.savez_compressed(path / "features.npz", X=X, feature_names=np.array(FEATURE_NAMES))
    lines = ["src_ip,dst_ip,src_port,dst_port,protocol"]
    lines += [f"10.0.0.5,{dst},40000,{port},TCP"] * len(X)
    (path / "flows.csv").write_text("\n".join(lines) + "\n")


def _trained(tmp_path):
    conn = connect(":memory:")
    seed_defaults(conn)
    run_training(conn, _benign(3000), tmp_path / "m", version="t1", n_estimators=50, activate=True)
    return conn


def test_benign_false_alarms_are_low_and_attacks_are_found(tmp_path):
    conn = _trained(tmp_path)
    _write_set(tmp_path / "b", _benign(2500, seed=11))
    _write_set(tmp_path / "a", _attack(300), dst="198.51.100.9", port="31337")

    report = evaluate(conn, [tmp_path / "b"], [tmp_path / "a"])

    assert report["benign"]["flows"] == 2500
    assert report["benign"]["at"]["global"]["rate"] < 0.03
    assert report["attack"]["at"]["global"]["rate"] > 0.95


def test_calibrated_threshold_stays_within_the_allowed_shift_of_global(tmp_path):
    conn = _trained(tmp_path)
    _write_set(tmp_path / "b", _benign(2500, seed=12))
    report = evaluate(conn, [tmp_path / "b"])
    assert abs(report["tau_calibrated"] - report["tau_global"]) <= 0.15 + 1e-9  # max_shift default


def test_flagged_flows_are_traced_to_their_destination(tmp_path):
    scores = np.array([0.9, 0.9, 0.2, 0.9])
    meta = [
        {"src_ip": "a", "dst_ip": "x", "dst_port": "1", "protocol": "TCP"},
        {"src_ip": "a", "dst_ip": "x", "dst_port": "1", "protocol": "TCP"},
        {"src_ip": "a", "dst_ip": "y", "dst_port": "2", "protocol": "UDP"},
        {"src_ip": "a", "dst_ip": "z", "dst_port": "3", "protocol": "TCP"},
    ]
    top = top_flagged(scores, 0.5, meta)
    assert top[0] == {"src": "a", "dst": "x", "dst_port": "1", "protocol": "TCP", "flows": 2}
    assert len(top) == 2  # the unflagged UDP flow is absent


def test_flow_meta_rows_line_up_with_the_stacked_matrix(tmp_path):
    _write_set(tmp_path / "one", _benign(4), port="80")
    _write_set(tmp_path / "two", _benign(3), port="53")
    meta = load_flow_meta([tmp_path / "one", tmp_path / "two"])
    assert [m["dst_port"] for m in meta] == ["80"] * 4 + ["53"] * 3


def test_evaluation_still_works_when_flows_csv_is_not_shipped(tmp_path):
    conn = _trained(tmp_path)
    _write_set(tmp_path / "b", _benign(2500, seed=13))
    (tmp_path / "b" / "flows.csv").unlink()
    report = evaluate(conn, [tmp_path / "b"])
    assert report["benign"]["flows"] == 2500
    assert report["benign_top_flagged_at_global"] == []
