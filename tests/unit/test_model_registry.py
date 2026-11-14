import json

import pytest

from common.db.migrate import connect
from models.compatibility import IncompatibleModel, check_model_package, verify_compatible
from models.registry import ModelRegistry
from training.feature_schema import current_extractor_version, feature_list_hash


def _reg():
    conn = connect(":memory:")
    return conn, ModelRegistry(conn)


def _add(reg, version, model_type="IFOREST", **kw):
    return reg.register(model_type, version, f"/models/{version}.joblib", feature_list_hash(),
                        current_extractor_version(), **kw)


def test_new_models_are_inactive_until_activated():
    _, reg = _reg()
    a = _add(reg, "v1")
    assert reg.active_id("IFOREST") is None
    reg.activate(a)
    assert reg.active_id("IFOREST") == a


def test_activating_flips_only_the_same_model_type():
    _, reg = _reg()
    iforest, rf = _add(reg, "v1"), _add(reg, "v1", "RF")
    reg.activate(iforest)
    reg.activate(rf)
    assert reg.active_id("IFOREST") == iforest
    assert reg.active_id("RF") == rf
    second = _add(reg, "v2")
    reg.activate(second)
    assert reg.active_id("IFOREST") == second
    assert reg.active_id("RF") == rf


def test_exactly_one_active_row_per_type_and_nothing_is_deleted():
    conn, reg = _reg()
    ids = [_add(reg, f"v{i}") for i in range(3)]
    for i in ids:
        reg.activate(i)
    active = conn.execute("SELECT COUNT(*) FROM model_package WHERE model_type='IFOREST' AND is_active=1").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM model_package").fetchone()[0]
    assert (active, total) == (1, 3)


def test_rollback_returns_to_the_model_that_was_replaced():
    _, reg = _reg()
    a, b, c = (_add(reg, v) for v in ("v1", "v2", "v3"))
    reg.activate(a)
    reg.activate(b)
    reg.activate(c)
    assert reg.rollback("IFOREST") == b
    assert reg.active_id("IFOREST") == b
    assert reg.rollback("IFOREST") == a


def test_rollback_with_no_history_raises():
    _, reg = _reg()
    reg.activate(_add(reg, "v1"))
    with pytest.raises(LookupError):
        reg.rollback("IFOREST")
    with pytest.raises(LookupError):
        reg.rollback("RF")


def test_activation_is_audited():
    conn, reg = _reg()
    a, b = _add(reg, "v1"), _add(reg, "v2")
    reg.activate(a)
    reg.activate(b)
    rows = conn.execute(
        "SELECT target, old_value, new_value FROM audit_log WHERE action='MODEL_ACTIVATE' ORDER BY audit_id"
    ).fetchall()
    assert rows == [("IFOREST", None, str(a)), ("IFOREST", str(a), str(b))]


def test_unknown_type_and_unknown_id_are_rejected():
    _, reg = _reg()
    with pytest.raises(ValueError):
        reg.register("SVM", "v1", "p", "h", "1.0")
    with pytest.raises(LookupError):
        reg.activate(999)


def test_metadata_round_trips_as_json():
    conn, reg = _reg()
    mid = _add(reg, "v1", metrics={"tau_global": 0.61}, training_data={"benign_only": True})
    reg.update_metrics(mid, {"tau_global": 0.7})
    metrics, td = conn.execute("SELECT metrics, training_data FROM model_package WHERE model_id=?", (mid,)).fetchone()
    assert json.loads(metrics) == {"tau_global": 0.7}
    assert json.loads(td) == {"benign_only": True}


def test_matching_feature_hash_is_accepted():
    conn, reg = _reg()
    mid = _add(reg, "v1")
    check_model_package(conn, mid)


def test_changed_feature_list_or_extractor_is_refused():
    with pytest.raises(IncompatibleModel):
        verify_compatible("0" * 64, current_extractor_version())
    with pytest.raises(IncompatibleModel):
        verify_compatible(feature_list_hash(), "0.0-old")


def test_hash_depends_on_order_and_version():
    base = feature_list_hash(["a", "b"], "1.0")
    assert feature_list_hash(["b", "a"], "1.0") != base
    assert feature_list_hash(["a", "b"], "1.1") != base
    assert feature_list_hash(["a", "b"], "1.0") == base
