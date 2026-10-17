# NIDPS Attack Classification (Layer 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `services/mlscorer/` — the Layer 3 attack classifier that sorts each flow into one
of 7 classes (or "Unknown") using a Random Forest or XGBoost model loaded from `model_package`, and
publishes `Evidence` for non-benign, non-unknown predictions onto the event bus.

**Architecture:** A single long-running service, `services/mlscorer/classifier_service.py`, consumes
`FLOW_READY` messages from `STREAM_FLOWS` (published by the separate, parallel flow-extraction
phase) with its own Redis consumer group `"layer3-classifier"`. For each flow it loads the 78
features from `flow_record`, scores them with the active RF/XGBoost model via
`services/mlscorer/classifier.py`'s `AttackClassifier` (implementing `common.detector.Detector`),
and — when the top-class confidence is at or above `fusion.theta_c` and the predicted class is not
`Benign` — publishes an `Evidence` message onto `STREAM_EVIDENCE`. The service writes nothing to the
database directly; it only reads `model_package` and `flow_record` and publishes bus messages.

**Tech Stack:** Python 3.11+, `scikit-learn` (`RandomForestClassifier`), `xgboost`
(`XGBClassifier`/`Booster`), `joblib`, `numpy`, `redis`/`fakeredis` (already in `requirements.txt`
from the common foundations phase), stdlib `sqlite3`/`json`, `pytest`.

## Global Constraints

- Python 3.11+ (spec Table: Technology Stack). All timestamps are UTC ISO 8601 strings produced only
  via `common.schemas.utc_now_iso()` — never call `datetime.now()` directly in this plan's code.
- **Table ownership:** this phase owns no tables for writing. It only reads `model_package` (to find
  the active RF/XGB classifier) and `flow_record` (to load a flow's 78 features by `flow_id`). The
  only output is `Evidence` messages published onto `STREAM_EVIDENCE` — the (separate, later) Event
  Store persists `evidence` rows from the bus, not this phase.
- **Security requirement (spec Section 6.6.2):** XGBoost models are always loaded from native JSON
  via `xgboost.Booster().load_model(file_path)` — this plan's code never calls `pickle.load`
  anywhere. Random Forest (scikit-learn) models are loaded via `joblib.load(file_path)`.
  `services/mlscorer/classifier.py` branches on `model_package.model_type` to choose between the two;
  there is no third branch and no fallback to `pickle`.
- **Model-loading bootstrap note:** the UML class diagram's `AttackClassifier.model: TreeEnsemble`
  attribute and "loads model from a model registry" behavior are realized here as
  `AttackClassifier.model: LoadedModel` (this plan's own dataclass) populated by reading the
  `model_package` table directly — no trained model exists yet from the offline training pipeline
  (a separate, later phase), and a dedicated `ModelRegistry` class is introduced by that phase. This
  module's `load_model_package()` is the bootstrap stand-in and is the one function a later
  `ModelRegistry` would replace.
- **`fusion.theta_c` ownership (FR-5.3):** this phase owns applying this threshold. `theta_c` is read
  fresh via `common.config_loader.get()` (through a local 5-second-TTL cache, not once at startup)
  so FR-10.6 ("apply config changes without restart") holds. When the predicted class's probability
  is below `theta_c`, the flow is labeled `"Unknown"` instead of the forced top class.
  `risk.weight_class` is read the same way and never hardcoded as `2.5` in code — only as a config
  default in `common/config_schema.py` (already fixed by Phase 1).
- **`STREAM_FLOWS` / `FLOW_READY` integration contract (built by a different, parallel phase — not
  implemented here):** per the master roadmap, Phase 3 (this plan) depends on Phase 2 (flow
  extraction) for the `FlowFeatures` schema and the `FLOW_READY` contract. This plan's
  `classifier_service.py` assumes Phase 2 has already added `STREAM_FLOWS = "nidps:flows"` to
  `common/bus.py` and `FLOW_READY = "flow_ready"` to `common.bus_messages.MessageType`, with payload
  shape `{"flow_id": int, "host_ip": str}`. If this plan is executed before Phase 2 lands, add those
  two one-line constants to `common/bus.py` and `common/bus_messages.py` first (mirroring how the
  decision-fusion-enforcement plan's Task 1 added `STREAM_HOST_SCORES`/`HOST_SCORE_UPDATED`) — that
  one-line addition is not part of this plan's task list because it is not this phase's output.
  This service consumes `STREAM_FLOWS` with consumer group `"layer3-classifier"`, which is
  independent of flow-extraction's own Layer-2 consumer group, so there is no infrastructure
  conflict.
- **`Evidence.flow_id` type bridging:** `FLOW_READY`'s `flow_id` field is a JSON integer (matching
  `flow_record.flow_id INTEGER PRIMARY KEY`), but `common.schemas.Evidence.flow_id` is typed
  `Optional[str]`. This plan's code casts with `str(flow_id)` when constructing `Evidence` and when
  building the `ScoringRequest` passed into `AttackClassifier.analyse()` — the integer form is only
  used for the `flow_record` lookup.
- **`flow_record.features` JSON shape (documented interpretation):** Phase 2's exact write format
  isn't specified beyond "TEXT-JSON", so this plan assumes it is the JSON serialization of
  `common.schemas.FlowFeatures` — i.e. `{"schema_version": "...", "values": [78 floats]}` — since
  that is the one fixed dataclass shape Phase 1 defines for a flow's features. `load_flow_features()`
  parses it into a `FlowFeatures` instance and calls its own `.validate()` method (schema version and
  length check) before using it; any parse or validation failure is treated as "skip this flow",
  never a crash.
- **Feature-schema mismatch handling (documented interpretation of "refuse to load a model whose
  feature schema doesn't match the current extractor"):** this is checked in two parts, both raising
  `services.mlscorer.classifier.ScoringSkipError` rather than letting an exception propagate and
  crash the consumer loop:
  1. At model-load time, `load_model_package()` compares the active `model_package` row's
     `feature_list_hash` against an `expected_feature_list_hash` string supplied by the caller
     (`classifier_service.run(expected_feature_list_hash=...)`, defaulting to the
     `NIDPS_FEATURE_LIST_HASH` environment variable). This plan does not invent its own hash
     algorithm for "the current extractor's feature schema" — that value is expected to be supplied
     by deployment tooling (a later phase) that knows what the running flow-extractor actually
     produces; if the two don't match, every flow is skipped (logged) until a matching model is
     deployed, but the service keeps running.
  2. At per-flow time, `verify_feature_schema()` compares the loaded model's own `extractor_version`
     against the specific flow's own `flow_record.extractor_version` column (recorded by Phase 2 at
     extraction time for that flow) — this catches a flow produced by a different extractor version
     than the one the deployed model was trained against, even if the model's hash check above
     passed. A mismatch here skips only that one flow, not the whole service.
- **Model/config caching for NFR-3 (≤10ms median scoring):** the loaded `AttackClassifier` and every
  config value are cached in-process with a 5-second TTL (`model_reload_interval_s` /
  `_ConfigCache`), so the hot path per flow is: one `flow_record` SELECT, one in-memory `predict()`
  call, and (for non-Benign/non-Unknown) one bus publish — no SQLite query against `model_package`
  or `config_setting` on every flow. This plan does not include a load-test harness (per the task
  brief); NFR-3 is a target to verify once the training pipeline produces a real deployed model.
- **Local TTL config cache, not `services.enforcer.config_cache.CachedConfig`:** the
  decision-fusion-enforcement phase (Phase 4) depends on this phase's `Evidence` output, not the
  other way around, so this plan does not import anything from `services/enforcer/`. Instead,
  `classifier_service.py` defines its own small private `_ConfigCache` class, since this plan's
  scope is limited to exactly `services/mlscorer/classifier.py` and
  `services/mlscorer/classifier_service.py`.
- **Class/probability ordering convention:** `AttackClassifier.predict()` always returns
  probabilities ordered to match `self.model.class_list` (itself parsed from
  `model_package.class_list`), regardless of how the underlying library orders its own classes
  internally. For Random Forest, `_rf_predict_fn()` reconciles scikit-learn's own
  (alphabetically-sorted) `model.classes_` ordering against `class_list` by name. For XGBoost,
  `_xgb_predict_fn()` relies on `class_list[i]` corresponding to training label `i` (the integer
  label fed to the model at training time) — this plan's tests construct both consistently.
- **Testing:** SQLite `:memory:` via `common.db.migrate.connect(":memory:")` for all DB tests;
  `fakeredis.FakeRedis(decode_responses=True)` wrapped in `common.bus.EventBus` for all bus tests.
  Unit tests fit small synthetic `RandomForestClassifier`/`XGBClassifier` models in-memory rather
  than requiring pretrained artifacts (no trained model exists yet — the offline training phase is
  separate and later). `model_package` rows needed for tests are inserted directly via SQL in test
  helper functions (`model_type='RF'` or `'XGB'`, `version='dev'`) — there is no model registry yet
  to insert through.

---

## File Structure

```
services/
  mlscorer/
    __init__.py
    classifier.py            # ScoringSkipError, LoadedModel, ScoringRequest,
                              #   fetch_active_model_row/load_model_package/verify_feature_schema,
                              #   load_flow_features, AttackClassifier(Detector)
    classifier_service.py    # entry point: STREAM_FLOWS consumer loop ("layer3-classifier" group),
                              #   _ConfigCache, heartbeat, Evidence publishing
tests/
  unit/
    test_classifier.py
  integration/
    test_classifier_service.py
requirements.txt             # MODIFIED: adds scikit-learn, xgboost, joblib, numpy
```

---

## Task 1: Package scaffolding for `services/mlscorer/`

**Files:**
- Create: `services/__init__.py` (idempotent — may already exist from a parallel phase; empty
  either way)
- Create: `services/mlscorer/__init__.py`
- Create: `tests/integration/__init__.py` (idempotent — may already exist from a parallel phase;
  empty either way)

**Interfaces:**
- Consumes: nothing.
- Produces: an importable `services.mlscorer` package and a `tests.integration` package that Tasks
  2-4 assume already exist.

- [ ] **Step 1: Create the package markers**

`services/__init__.py`:
```python
```

`services/mlscorer/__init__.py`:
```python
```

`tests/integration/__init__.py`:
```python
```

- [ ] **Step 2: Verify the packages import cleanly**

Run:
```bash
.venv/Scripts/python -c "import services.mlscorer, tests.integration; print('ok')"
```
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add services/__init__.py services/mlscorer/__init__.py tests/integration/__init__.py
git commit -m "chore: scaffold services/mlscorer package"
```

---

## Task 2: Model loading from `model_package` (`services/mlscorer/classifier.py`, part 1)

**Files:**
- Modify: `requirements.txt`
- Create: `services/mlscorer/classifier.py`
- Test: `tests/unit/test_classifier.py`

**Interfaces:**
- Consumes: `common.db.migrate.connect` (Phase 1, for tests only).
- Produces: `ScoringSkipError` exception; `LoadedModel` dataclass (`model_id`, `model_type`,
  `extractor_version`, `feature_list_hash`, `class_list`, `predict_proba_fn`);
  `fetch_active_model_row(conn) -> Optional[tuple]`;
  `load_model_package(conn, expected_feature_list_hash: str) -> LoadedModel`;
  `verify_feature_schema(model: LoadedModel, flow_extractor_version: str) -> None`. Task 3's
  `AttackClassifier` wraps a `LoadedModel`; Task 4's `classifier_service.py` calls
  `load_model_package()` and `verify_feature_schema()` directly.

- [ ] **Step 1: Add ML dependencies to `requirements.txt`**

Append to `requirements.txt`:
```
scikit-learn>=1.3,<2.0
xgboost>=2.0,<3.0
joblib>=1.3,<2.0
numpy>=1.24,<2.0
```

Run:
```bash
.venv/Scripts/pip install -r requirements.txt
```
Expected: packages install without error.

- [ ] **Step 2: Write the failing tests**

```python
# tests/unit/test_classifier.py
import json

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from common.db.migrate import connect
from services.mlscorer.classifier import (
    LoadedModel,
    ScoringSkipError,
    fetch_active_model_row,
    load_model_package,
    verify_feature_schema,
)

CLASS_LIST = [
    "Benign",
    "Reconnaissance",
    "Brute Force",
    "DoS/DDoS",
    "Botnet/C2",
    "Spoofing",
    "Infiltration/Lateral Movement",
]


def _insert_model_row(
    conn,
    model_type,
    file_path,
    feature_list_hash="hash-abc",
    extractor_version="ev-1",
    class_list=CLASS_LIST,
    is_active=1,
):
    conn.execute(
        """INSERT INTO model_package
           (model_type, version, file_path, feature_list_hash, extractor_version, class_list,
            is_active)
           VALUES (?, 'dev', ?, ?, ?, ?, ?)""",
        (model_type, file_path, feature_list_hash, extractor_version, json.dumps(class_list), is_active),
    )
    conn.commit()


def _fit_rf():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(70, 78))
    y = np.array([CLASS_LIST[i % 7] for i in range(70)])
    model = RandomForestClassifier(n_estimators=5, max_features="sqrt", random_state=0)
    model.fit(X, y)
    return model, X[0].tolist()


def test_load_model_package_raises_when_no_active_model():
    conn = connect(":memory:")

    with pytest.raises(ScoringSkipError):
        load_model_package(conn, expected_feature_list_hash="hash-abc")


def test_load_model_package_raises_on_feature_list_hash_mismatch(tmp_path):
    conn = connect(":memory:")
    model, _ = _fit_rf()
    file_path = str(tmp_path / "rf.joblib")
    joblib.dump(model, file_path)
    _insert_model_row(conn, "RF", file_path, feature_list_hash="hash-abc")

    with pytest.raises(ScoringSkipError):
        load_model_package(conn, expected_feature_list_hash="hash-DIFFERENT")


def test_load_model_package_loads_random_forest_via_joblib(tmp_path):
    conn = connect(":memory:")
    model, sample = _fit_rf()
    file_path = str(tmp_path / "rf.joblib")
    joblib.dump(model, file_path)
    _insert_model_row(conn, "RF", file_path, feature_list_hash="hash-abc")

    loaded = load_model_package(conn, expected_feature_list_hash="hash-abc")

    assert loaded.model_type == "RF"
    assert loaded.class_list == CLASS_LIST
    probabilities = loaded.predict_proba_fn(sample)
    assert len(probabilities) == 7
    assert abs(sum(probabilities) - 1.0) < 1e-6


def test_load_model_package_loads_xgboost_via_native_json_never_pickle(tmp_path, monkeypatch):
    pytest.importorskip("xgboost")
    from xgboost import XGBClassifier

    rng = np.random.default_rng(1)
    X = rng.normal(size=(70, 78))
    y = np.array([i % 7 for i in range(70)])
    model = XGBClassifier(n_estimators=5, max_depth=2, gamma=0.1, reg_lambda=1.0)
    model.fit(X, y)

    file_path = str(tmp_path / "xgb_model.json")
    model.save_model(file_path)

    conn = connect(":memory:")
    _insert_model_row(conn, "XGB", file_path, feature_list_hash="hash-xyz")

    def _forbidden_pickle_load(*args, **kwargs):
        raise AssertionError("pickle.load must never be called when loading an XGB model")

    monkeypatch.setattr("pickle.load", _forbidden_pickle_load)

    loaded = load_model_package(conn, expected_feature_list_hash="hash-xyz")

    assert loaded.model_type == "XGB"
    probabilities = loaded.predict_proba_fn(X[0].tolist())
    assert len(probabilities) == 7
    assert abs(sum(probabilities) - 1.0) < 1e-4


def test_fetch_active_model_row_ignores_inactive_rows(tmp_path):
    conn = connect(":memory:")
    model, _ = _fit_rf()
    file_path = str(tmp_path / "rf.joblib")
    joblib.dump(model, file_path)
    _insert_model_row(conn, "RF", file_path, is_active=0)

    assert fetch_active_model_row(conn) is None


def test_verify_feature_schema_raises_on_version_mismatch():
    model = LoadedModel(
        model_id=1,
        model_type="RF",
        extractor_version="ev-1",
        feature_list_hash="hash-abc",
        class_list=CLASS_LIST,
        predict_proba_fn=lambda features: [1.0, 0, 0, 0, 0, 0, 0],
    )

    with pytest.raises(ScoringSkipError):
        verify_feature_schema(model, "ev-DIFFERENT")


def test_verify_feature_schema_passes_on_matching_version():
    model = LoadedModel(
        model_id=1,
        model_type="RF",
        extractor_version="ev-1",
        feature_list_hash="hash-abc",
        class_list=CLASS_LIST,
        predict_proba_fn=lambda features: [1.0, 0, 0, 0, 0, 0, 0],
    )

    verify_feature_schema(model, "ev-1")  # must not raise
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_classifier.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer.classifier'`

- [ ] **Step 4: Write `services/mlscorer/classifier.py` (part 1)**

```python
"""Layer 3 attack classifier (FR-5.1-5.3): loads the active RF/XGBoost model from
model_package and scores a flow's 78 features into one of 7 classes, or 'Unknown' when the
top-class confidence is below fusion.theta_c. XGBoost models are ALWAYS loaded from native
JSON via xgboost.Booster.load_model() -- this module never calls pickle.load (spec Section
6.6.2: pickle deserialization executes arbitrary code, a risk for a model file an admin might
later replace). A full ModelRegistry class is introduced by the later training/model-registry
phase; this module reads model_package directly as a bootstrap stand-in."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Callable, Optional

import joblib
import numpy as np
import xgboost as xgb


class ScoringSkipError(Exception):
    """Raised for any condition that means 'do not score this flow' -- no active/matching
    model, malformed feature JSON, wrong feature count, or a flow/model extractor-version
    mismatch. The service layer catches exactly this one exception type, logs it, and moves on
    to the next flow; it must never let a bad model or a bad row crash the consumer loop."""


@dataclass
class LoadedModel:
    model_id: int
    model_type: str  # 'RF' or 'XGB'
    extractor_version: str
    feature_list_hash: str
    class_list: list
    predict_proba_fn: Callable[[list], list]


def fetch_active_model_row(conn: sqlite3.Connection) -> Optional[tuple]:
    return conn.execute(
        """SELECT model_id, model_type, file_path, feature_list_hash, extractor_version, class_list
           FROM model_package
           WHERE model_type IN ('RF', 'XGB') AND is_active = 1
           ORDER BY deployed_at DESC
           LIMIT 1"""
    ).fetchone()


def _rf_predict_fn(sk_model, class_list: list) -> Callable[[list], list]:
    model_classes = list(sk_model.classes_)

    def predict(features: list) -> list:
        proba = sk_model.predict_proba([features])[0]
        by_class = dict(zip(model_classes, proba))
        return [float(by_class.get(name, 0.0)) for name in class_list]

    return predict


def _xgb_predict_fn(booster, class_list: list) -> Callable[[list], list]:
    def predict(features: list) -> list:
        dmatrix = xgb.DMatrix(np.array([features], dtype=float))
        proba = booster.predict(dmatrix)[0]
        return [float(p) for p in proba]

    return predict


def load_model_package(conn: sqlite3.Connection, expected_feature_list_hash: str) -> LoadedModel:
    row = fetch_active_model_row(conn)
    if row is None:
        raise ScoringSkipError("no active RF/XGB model_package row found")

    model_id, model_type, file_path, feature_list_hash, extractor_version, class_list_json = row
    if feature_list_hash != expected_feature_list_hash:
        raise ScoringSkipError(
            f"model {model_id} feature_list_hash={feature_list_hash!r} does not match "
            f"current extractor's feature_list_hash={expected_feature_list_hash!r}"
        )

    class_list = json.loads(class_list_json)
    if model_type == "RF":
        sk_model = joblib.load(file_path)
        predict_fn = _rf_predict_fn(sk_model, class_list)
    elif model_type == "XGB":
        booster = xgb.Booster()
        booster.load_model(file_path)
        predict_fn = _xgb_predict_fn(booster, class_list)
    else:
        raise ScoringSkipError(f"unsupported model_type {model_type!r}")

    return LoadedModel(
        model_id=model_id,
        model_type=model_type,
        extractor_version=extractor_version,
        feature_list_hash=feature_list_hash,
        class_list=class_list,
        predict_proba_fn=predict_fn,
    )


def verify_feature_schema(model: LoadedModel, flow_extractor_version: str) -> None:
    if model.extractor_version != flow_extractor_version:
        raise ScoringSkipError(
            f"model {model.model_id} extractor_version={model.extractor_version!r} does not "
            f"match this flow's extractor_version={flow_extractor_version!r}"
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_classifier.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
git add requirements.txt services/mlscorer/classifier.py tests/unit/test_classifier.py
git commit -m "feat: add RF/XGBoost model loading for Layer 3 classifier (never pickle)"
```

---

## Task 3: Flow feature loading and `AttackClassifier` (`services/mlscorer/classifier.py`, part 2)

**Files:**
- Modify: `services/mlscorer/classifier.py`
- Modify: `tests/unit/test_classifier.py`

**Interfaces:**
- Consumes: `common.detector.Detector` (Phase 1); `common.schemas.{ComponentHealth, Evidence,
  EvidenceType, FlowFeatures, HealthState, Layer, utc_now_iso}` (Phase 1); this task's own
  `LoadedModel`/`ScoringSkipError` (Task 2).
- Produces: `ScoringRequest` dataclass (`flow_id: str`, `host_ip: str`, `features: list`,
  `theta_c: float`, `weight_class: float`); `load_flow_features(conn, flow_id: int) -> tuple[list,
  str]` (values, extractor_version); `AttackClassifier(Detector)` with `model: LoadedModel`,
  `predict(features: list) -> list`, `classify(features: list, theta_c: float) -> tuple[str,
  float]`, `analyse(item: ScoringRequest) -> Optional[list[Evidence]]`, `heartbeat() ->
  ComponentHealth`. Task 4's `classifier_service.py` constructs one `AttackClassifier` per loaded
  model and calls `load_flow_features()`, `verify_feature_schema()` (Task 2), and
  `classifier.analyse()` per `FLOW_READY` message.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_classifier.py`:
```python
from common.schemas import FEATURE_COUNT, SCHEMA_VERSION, EvidenceType, HealthState, Layer

from services.mlscorer.classifier import (
    AttackClassifier,
    ScoringRequest,
    load_flow_features,
)


def _fake_model(class_list, fixed_probabilities):
    return LoadedModel(
        model_id=1,
        model_type="RF",
        extractor_version="ev-1",
        feature_list_hash="hash-abc",
        class_list=class_list,
        predict_proba_fn=lambda features: fixed_probabilities,
    )


def _insert_host_and_flow(conn, features_json="__default__", extractor_version="ev-1"):
    conn.execute("INSERT INTO host (host_id, ip_address, is_internal) VALUES (1, '10.0.0.5', 1)")
    if features_json == "__default__":
        features_json = json.dumps({"schema_version": SCHEMA_VERSION, "values": [0.1] * FEATURE_COUNT})
    conn.execute(
        """INSERT INTO flow_record
           (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
            features, extractor_version)
           VALUES (1, '10.0.0.5', '10.0.0.9', 1234, 80, 'TCP', '2026-10-10T00:00:00.000000Z',
                   '2026-10-10T00:00:01.000000Z', ?, ?)""",
        (features_json, extractor_version),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def test_load_flow_features_returns_values_and_extractor_version():
    conn = connect(":memory:")
    flow_id = _insert_host_and_flow(conn)

    values, extractor_version = load_flow_features(conn, flow_id)

    assert len(values) == FEATURE_COUNT
    assert extractor_version == "ev-1"


def test_load_flow_features_raises_when_flow_not_found():
    conn = connect(":memory:")

    with pytest.raises(ScoringSkipError):
        load_flow_features(conn, 999)


def test_load_flow_features_raises_on_malformed_json():
    conn = connect(":memory:")
    flow_id = _insert_host_and_flow(conn, features_json="not-json")

    with pytest.raises(ScoringSkipError):
        load_flow_features(conn, flow_id)


def test_load_flow_features_raises_on_wrong_feature_count():
    conn = connect(":memory:")
    bad_json = json.dumps({"schema_version": SCHEMA_VERSION, "values": [0.1] * 10})
    flow_id = _insert_host_and_flow(conn, features_json=bad_json)

    with pytest.raises(ScoringSkipError):
        load_flow_features(conn, flow_id)


def test_classify_returns_class_name_when_confidence_above_theta():
    model = _fake_model(CLASS_LIST, [0.02, 0.9, 0.02, 0.02, 0.02, 0.01, 0.01])
    classifier = AttackClassifier(model)

    predicted_class, confidence = classifier.classify([0.0] * 78, theta_c=0.5)

    assert predicted_class == "Reconnaissance"
    assert confidence == 0.9


def test_classify_returns_unknown_when_confidence_below_theta():
    model = _fake_model(CLASS_LIST, [0.3, 0.3, 0.1, 0.1, 0.1, 0.05, 0.05])
    classifier = AttackClassifier(model)

    predicted_class, confidence = classifier.classify([0.0] * 78, theta_c=0.5)

    assert predicted_class == "Unknown"
    assert confidence == 0.3


def test_analyse_returns_evidence_for_non_benign_class():
    model = _fake_model(CLASS_LIST, [0.02, 0.9, 0.02, 0.02, 0.02, 0.01, 0.01])
    classifier = AttackClassifier(model)
    request = ScoringRequest(
        flow_id="42", host_ip="10.0.0.5", features=[0.0] * 78, theta_c=0.5, weight_class=2.5
    )

    evidence_list = classifier.analyse(request)

    assert evidence_list is not None
    evidence = evidence_list[0]
    assert evidence.source == Layer.L3_CLASSIFIER
    assert evidence.kind == EvidenceType.CLASS
    assert evidence.predicted_class == "Reconnaissance"
    assert evidence.confidence == 0.9
    assert evidence.strength == 0.9
    assert evidence.weight == 2.5
    assert evidence.flow_id == "42"
    assert evidence.host_ip == "10.0.0.5"
    assert evidence.model_id == 1


def test_analyse_returns_none_for_benign_prediction():
    model = _fake_model(CLASS_LIST, [0.95, 0.01, 0.01, 0.01, 0.01, 0.005, 0.005])
    classifier = AttackClassifier(model)
    request = ScoringRequest(
        flow_id="1", host_ip="10.0.0.5", features=[0.0] * 78, theta_c=0.5, weight_class=2.5
    )

    assert classifier.analyse(request) is None


def test_analyse_returns_none_for_unknown_prediction():
    model = _fake_model(CLASS_LIST, [0.3, 0.3, 0.1, 0.1, 0.1, 0.05, 0.05])
    classifier = AttackClassifier(model)
    request = ScoringRequest(
        flow_id="1", host_ip="10.0.0.5", features=[0.0] * 78, theta_c=0.5, weight_class=2.5
    )

    assert classifier.analyse(request) is None


def test_heartbeat_returns_normal_health():
    model = _fake_model(CLASS_LIST, [1.0, 0, 0, 0, 0, 0, 0])
    classifier = AttackClassifier(model)

    health = classifier.heartbeat()

    assert health.name == "mlscorer"
    assert health.state == HealthState.NORMAL
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_classifier.py -v`
Expected: FAIL with `ImportError: cannot import name 'AttackClassifier' from
'services.mlscorer.classifier'`

- [ ] **Step 3: Append to `services/mlscorer/classifier.py`**

Add these imports to the top of the file (alongside the existing ones from Task 2):
```python
from common.detector import Detector
from common.schemas import (
    ComponentHealth,
    Evidence,
    EvidenceType,
    FlowFeatures,
    HealthState,
    Layer,
    utc_now_iso,
)

UNKNOWN_CLASS = "Unknown"
BENIGN_CLASS = "Benign"
```

Append to the end of the file:
```python
@dataclass
class ScoringRequest:
    flow_id: str
    host_ip: str
    features: list
    theta_c: float
    weight_class: float


def load_flow_features(conn: sqlite3.Connection, flow_id: int) -> tuple:
    row = conn.execute(
        "SELECT features, extractor_version FROM flow_record WHERE flow_id = ?", (flow_id,)
    ).fetchone()
    if row is None:
        raise ScoringSkipError(f"flow_record {flow_id} not found")

    features_json, extractor_version = row
    try:
        parsed = json.loads(features_json)
        flow_features = FlowFeatures(
            schema_version=parsed["schema_version"], values=parsed["values"]
        )
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ScoringSkipError(f"flow_record {flow_id} has malformed features JSON: {exc}") from exc

    if not flow_features.validate():
        raise ScoringSkipError(
            f"flow_record {flow_id} features failed schema validation "
            f"(schema_version={flow_features.schema_version!r}, "
            f"count={len(flow_features.values)})"
        )
    return flow_features.values, extractor_version


class AttackClassifier(Detector):
    """Implements the Detector interface for Layer 3 (FR-5.1-5.3). attr `model` corresponds to
    the UML's `model: TreeEnsemble` attribute -- realized here as a LoadedModel wrapping either
    a fitted RandomForestClassifier (via joblib) or an xgboost.Booster (via native JSON)."""

    name = "mlscorer"

    def __init__(self, model: LoadedModel):
        self.model = model

    def predict(self, features: list) -> list:
        """Returns per-class probabilities, aligned index-for-index with self.model.class_list."""
        return self.model.predict_proba_fn(features)

    def classify(self, features: list, theta_c: float) -> tuple:
        probabilities = self.predict(features)
        best_idx = max(range(len(probabilities)), key=lambda i: probabilities[i])
        confidence = probabilities[best_idx]
        if confidence < theta_c:
            return UNKNOWN_CLASS, confidence
        return self.model.class_list[best_idx], confidence

    def analyse(self, item: ScoringRequest) -> Optional[list]:
        predicted_class, confidence = self.classify(item.features, item.theta_c)
        if predicted_class in (UNKNOWN_CLASS, BENIGN_CLASS):
            return None
        evidence = Evidence(
            source=Layer.L3_CLASSIFIER,
            flow_id=item.flow_id,
            host_ip=item.host_ip,
            kind=EvidenceType.CLASS,
            strength=confidence,
            weight=item.weight_class,
            predicted_class=predicted_class,
            confidence=confidence,
            model_id=self.model.model_id,
        )
        return [evidence]

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_classifier.py -v`
Expected: 17 passed

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/classifier.py tests/unit/test_classifier.py
git commit -m "feat: add AttackClassifier Detector implementation (FR-5.1-5.3)"
```

---

## Task 4: Classifier service entry point (`services/mlscorer/classifier_service.py`)

**Files:**
- Create: `services/mlscorer/classifier_service.py`
- Test: `tests/integration/test_classifier_service.py`

**Interfaces:**
- Consumes: `common.bus.{EventBus, STREAM_EVIDENCE, STREAM_FLOWS, STREAM_HEARTBEATS}` (Phase 1 +
  Phase 2's `STREAM_FLOWS` addition — see Global Constraints); `common.bus_messages.{MessageType,
  decode_envelope, encode_envelope}` (Phase 1 + Phase 2's `FLOW_READY` addition);
  `common.config_loader.{get, seed_defaults}`, `common.db.migrate.connect`,
  `common.logging_setup.configure_logging`, `common.schemas.{ComponentHealth, HealthState,
  utc_now_iso}` (Phase 1); `services.mlscorer.classifier.{AttackClassifier, ScoringRequest,
  ScoringSkipError, load_flow_features, load_model_package, verify_feature_schema}` (Tasks 2, 3).
- Produces: `run(conn=None, bus=None, db_path="nidps.db", redis_url="redis://localhost:6379/0",
  expected_feature_list_hash=None, model_reload_interval_s=5.0, poll_interval_s=0.5,
  stop_after_iterations=None) -> None`. Process entry point for `python -m
  services.mlscorer.classifier_service`, invoked by a later systemd phase.

- [ ] **Step 1: Write the failing integration test**

```python
# tests/integration/test_classifier_service.py
import json

import fakeredis
import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import FEATURE_COUNT, SCHEMA_VERSION

try:
    from common.bus import STREAM_FLOWS
except ImportError:  # pragma: no cover - exercised only before Phase 2 lands
    pytest.skip(
        "common.bus.STREAM_FLOWS not defined yet -- see this plan's Global Constraints on the "
        "Phase 2 integration contract",
        allow_module_level=True,
    )

from services.mlscorer.classifier_service import run

CLASS_LIST = [
    "Benign",
    "Reconnaissance",
    "Brute Force",
    "DoS/DDoS",
    "Botnet/C2",
    "Spoofing",
    "Infiltration/Lateral Movement",
]


def _fit_separated_rf(tmp_path):
    rng = np.random.default_rng(42)
    X, y = [], []
    for idx, label in enumerate(CLASS_LIST):
        center = np.full(FEATURE_COUNT, idx * 10.0)
        for _ in range(20):
            X.append(center + rng.normal(scale=0.1, size=FEATURE_COUNT))
            y.append(label)
    model = RandomForestClassifier(n_estimators=20, max_features="sqrt", random_state=0)
    model.fit(np.array(X), np.array(y))

    file_path = str(tmp_path / "rf.joblib")
    joblib.dump(model, file_path)
    reconnaissance_sample = np.full(FEATURE_COUNT, 1 * 10.0).tolist()
    return file_path, reconnaissance_sample


def test_run_scores_flow_and_publishes_evidence_and_heartbeat(tmp_path):
    conn = connect(":memory:")
    seed_defaults(conn)
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    bus = EventBus(fake_redis)

    file_path, sample_features = _fit_separated_rf(tmp_path)
    conn.execute(
        """INSERT INTO model_package
           (model_type, version, file_path, feature_list_hash, extractor_version, class_list,
            is_active)
           VALUES ('RF', 'dev', ?, 'hash-abc', 'ev-1', ?, 1)""",
        (file_path, json.dumps(CLASS_LIST)),
    )
    conn.execute("INSERT INTO host (host_id, ip_address, is_internal) VALUES (1, '10.0.0.5', 1)")
    features_json = json.dumps({"schema_version": SCHEMA_VERSION, "values": sample_features})
    conn.execute(
        """INSERT INTO flow_record
           (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
            features, extractor_version)
           VALUES (1, '10.0.0.5', '10.0.0.9', 1234, 80, 'TCP', '2026-10-10T00:00:00.000000Z',
                   '2026-10-10T00:00:01.000000Z', ?, 'ev-1')""",
        (features_json,),
    )
    conn.commit()
    flow_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    bus.publish(
        STREAM_FLOWS,
        encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"}),
    )

    run(
        conn=conn,
        bus=bus,
        expected_feature_list_hash="hash-abc",
        poll_interval_s=0.1,
        stop_after_iterations=1,
    )

    evidence_messages = []
    bus.consume(
        STREAM_EVIDENCE, group="test-evidence", consumer="c1", handler=evidence_messages.append,
        block_ms=100,
    )
    assert len(evidence_messages) == 1
    payload = decode_envelope(evidence_messages[0])["payload"]
    assert payload["predicted_class"] == "Reconnaissance"
    assert payload["confidence"] > 0.5
    assert payload["flow_id"] == str(flow_id)
    assert payload["host_ip"] == "10.0.0.5"

    heartbeats = []
    bus.consume(
        STREAM_HEARTBEATS, group="test-heartbeats", consumer="c1", handler=heartbeats.append,
        block_ms=100,
    )
    assert len(heartbeats) == 1
    assert decode_envelope(heartbeats[0])["payload"]["name"] == "mlscorer"


def test_run_skips_flow_without_crashing_on_schema_mismatch(tmp_path):
    conn = connect(":memory:")
    seed_defaults(conn)
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    bus = EventBus(fake_redis)

    file_path, sample_features = _fit_separated_rf(tmp_path)
    conn.execute(
        """INSERT INTO model_package
           (model_type, version, file_path, feature_list_hash, extractor_version, class_list,
            is_active)
           VALUES ('RF', 'dev', ?, 'hash-abc', 'ev-1', ?, 1)""",
        (file_path, json.dumps(CLASS_LIST)),
    )
    conn.execute("INSERT INTO host (host_id, ip_address, is_internal) VALUES (1, '10.0.0.5', 1)")
    features_json = json.dumps({"schema_version": SCHEMA_VERSION, "values": sample_features})
    conn.execute(
        """INSERT INTO flow_record
           (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
            features, extractor_version)
           VALUES (1, '10.0.0.5', '10.0.0.9', 1234, 80, 'TCP', '2026-10-10T00:00:00.000000Z',
                   '2026-10-10T00:00:01.000000Z', ?, 'ev-DIFFERENT')""",
        (features_json,),
    )
    conn.commit()
    flow_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    bus.publish(
        STREAM_FLOWS,
        encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"}),
    )

    # Must not raise, even though this flow's extractor_version ('ev-DIFFERENT') doesn't match
    # the deployed model's extractor_version ('ev-1').
    run(
        conn=conn,
        bus=bus,
        expected_feature_list_hash="hash-abc",
        poll_interval_s=0.1,
        stop_after_iterations=1,
    )

    evidence_messages = []
    bus.consume(
        STREAM_EVIDENCE, group="test-evidence-2", consumer="c1", handler=evidence_messages.append,
        block_ms=100,
    )
    assert evidence_messages == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/integration/test_classifier_service.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer.classifier_service'`
(or the module-level `pytest.skip` if `STREAM_FLOWS` doesn't exist yet in this checkout — see Global
Constraints on the Phase 2 dependency).

- [ ] **Step 3: Write `services/mlscorer/classifier_service.py`**

```python
"""Layer 3 classifier service entry point (FR-5.1-5.3): consumes FLOW_READY from STREAM_FLOWS
with its OWN consumer group 'layer3-classifier' (independent of flow-extraction's Layer-2
consumer group -- see this plan's Global Constraints on the STREAM_FLOWS integration contract),
loads each flow's 78 features from flow_record, scores them with the active RF/XGBoost model,
and publishes Evidence onto STREAM_EVIDENCE for non-Benign/non-Unknown predictions. Publishes a
heartbeat onto STREAM_HEARTBEATS at watchdog.heartbeat_interval_s so the (separate) watchdog
phase can supervise this process."""
from __future__ import annotations

import os
import time
from typing import Optional

from common import config_loader
from common.bus import STREAM_EVIDENCE, STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, HealthState, utc_now_iso

from services.mlscorer.classifier import (
    AttackClassifier,
    ScoringRequest,
    ScoringSkipError,
    load_flow_features,
    load_model_package,
    verify_feature_schema,
)

COMPONENT_NAME = "mlscorer"
CONSUMER_GROUP = "layer3-classifier"


class _ConfigCache:
    """Small TTL cache over common.config_loader.get(), local to this service (FR-10.6). Not
    services.enforcer.config_cache.CachedConfig: the decision-fusion-enforcement phase depends
    on this phase's Evidence output, not the reverse, and this plan's scope is limited to
    services/mlscorer/classifier.py and classifier_service.py."""

    def __init__(self, conn, ttl_s: float = 5.0, now_fn=time.time):
        self._conn = conn
        self._ttl_s = ttl_s
        self._now_fn = now_fn
        self._cache: dict = {}

    def get(self, key: str):
        now = self._now_fn()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        value = config_loader.get(self._conn, key)
        self._cache[key] = (now, value)
        return value


def run(
    conn=None,
    bus: Optional[EventBus] = None,
    db_path: str = "nidps.db",
    redis_url: str = "redis://localhost:6379/0",
    expected_feature_list_hash: Optional[str] = None,
    model_reload_interval_s: float = 5.0,
    poll_interval_s: float = 0.5,
    stop_after_iterations: Optional[int] = None,
) -> None:
    logger = configure_logging(COMPONENT_NAME)
    conn = conn or connect(db_path)
    seed_defaults(conn)
    bus = bus or EventBus.from_url(redis_url)
    config_cache = _ConfigCache(conn)

    if expected_feature_list_hash is None:
        expected_feature_list_hash = os.environ.get("NIDPS_FEATURE_LIST_HASH", "")

    model_state = {"classifier": None, "last_load_attempt": 0.0}

    def _get_classifier() -> AttackClassifier:
        now = time.time()
        if (
            model_state["classifier"] is None
            or now - model_state["last_load_attempt"] >= model_reload_interval_s
        ):
            model_state["last_load_attempt"] = now
            loaded = load_model_package(conn, expected_feature_list_hash)
            model_state["classifier"] = AttackClassifier(loaded)
        return model_state["classifier"]

    def handle_raw(raw: str) -> None:
        envelope = decode_envelope(raw)
        if envelope["type"] != MessageType.FLOW_READY.value:
            return

        flow_id = envelope["payload"]["flow_id"]
        host_ip = envelope["payload"]["host_ip"]
        try:
            classifier = _get_classifier()
            features, flow_extractor_version = load_flow_features(conn, flow_id)
            verify_feature_schema(classifier.model, flow_extractor_version)
        except ScoringSkipError as exc:
            logger.error("skipping flow_id=%s: %s", flow_id, exc)
            return

        request = ScoringRequest(
            flow_id=str(flow_id),
            host_ip=host_ip,
            features=features,
            theta_c=config_cache.get("fusion.theta_c"),
            weight_class=config_cache.get("risk.weight_class"),
        )
        evidence_list = classifier.analyse(request)
        if not evidence_list:
            return
        for evidence in evidence_list:
            bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, evidence))
            logger.info(
                "published CLASS evidence flow_id=%s class=%s confidence=%.3f",
                flow_id, evidence.predicted_class, evidence.confidence,
            )

    last_heartbeat = 0.0
    iterations = 0
    while stop_after_iterations is None or iterations < stop_after_iterations:
        bus.consume(
            STREAM_FLOWS,
            group=CONSUMER_GROUP,
            consumer=f"{CONSUMER_GROUP}-1",
            handler=handle_raw,
            count=10,
            block_ms=int(poll_interval_s * 1000),
        )

        now = time.time()
        heartbeat_interval = config_cache.get("watchdog.heartbeat_interval_s")
        if now - last_heartbeat >= heartbeat_interval:
            health = ComponentHealth(
                name=COMPONENT_NAME, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
            )
            bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))
            last_heartbeat = now
        iterations += 1


if __name__ == "__main__":
    run()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/integration/test_classifier_service.py -v`
Expected: 2 passed (or skipped with the message from Step 1 if `STREAM_FLOWS` doesn't exist yet in
this checkout).

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/classifier_service.py tests/integration/test_classifier_service.py
git commit -m "feat: add Layer 3 classifier service entry point"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:** FR-5.1 (7-class sort via RF/XGBoost) → Task 3's `AttackClassifier.classify()`
  and Task 2's `load_model_package()` branching on `model_type`. FR-5.2 (confidence per
  classification) → `classify()`'s returned `confidence`, carried onto `Evidence.confidence`. FR-5.3
  (label "Unknown" below `theta_c`) → `classify()`'s threshold check, tested explicitly in Task 3
  (`test_classify_returns_unknown_when_confidence_below_theta`). NFR-3 (≤10ms median scoring) →
  addressed structurally (in-memory predict, TTL-cached model/config, no load-test harness per the
  task brief) and called out in Global Constraints. Eq 5.6 (Gini splits, `sqrt(d)` features) →
  `RandomForestClassifier(criterion` defaults to `'gini'`, explicit `max_features="sqrt"`) in Task 2.
  Eq 5.7 (`gamma`, `reg_lambda`) → `XGBClassifier(gamma=..., reg_lambda=...)` in Task 2's test,
  documented as the library's own parameters, not re-implemented. Section 6.6.2 (never pickle for
  XGBoost) → `test_load_model_package_loads_xgboost_via_native_json_never_pickle` monkeypatches
  `pickle.load` to assert it's never called. "Refuse to load a model whose feature schema doesn't
  match the current extractor" → Task 2's `verify_feature_schema()` plus `load_model_package()`'s
  hash check, both raising `ScoringSkipError` rather than crashing, tested in Task 4's
  `test_run_skips_flow_without_crashing_on_schema_mismatch`.
- **Placeholder scan:** none found — every step has complete, runnable code and literal expected
  output; no "TODO"/"handle appropriately"/"similar to Task N" text appears anywhere in this plan.
- **Type consistency:** `AttackClassifier.model` is always a `LoadedModel` (Task 2's dataclass)
  everywhere it's referenced (Task 3's `classify()`/`analyse()`, Task 4's
  `verify_feature_schema(classifier.model, ...)`). `ScoringRequest.flow_id` is `str` everywhere
  (Task 3's tests, Task 4's `str(flow_id)` cast before constructing it) matching
  `common.schemas.Evidence.flow_id: Optional[str]`. `ScoringSkipError` is the one exception type
  raised by every "skip this flow" path across both `classifier.py` (Task 2's `load_model_package`,
  `verify_feature_schema`; Task 3's `load_flow_features`) and caught in exactly one place in
  `classifier_service.py` (Task 4's `handle_raw`) — no second ad hoc exception type was introduced.
  `CLASS_LIST` (the 7 class names) is spelled identically across Task 2's, Task 3's, and Task 4's
  test files, matching the exact 7 names given in the task brief.
