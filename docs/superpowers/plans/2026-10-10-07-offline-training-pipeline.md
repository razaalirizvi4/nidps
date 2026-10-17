# NIDPS Offline Training Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the offline training pipeline (`training/`) and model registry (`models/`) that
produce, evaluate, package, and version-control the three models the live NIDPS device loads:
Layer 2's Isolation Forest (anomaly), and Layer 3's Random Forest and XGBoost (7-class attack
classification) — runs on a separate training workstation, never on the Raspberry Pi.

**Architecture:** A dataset builder re-processes raw PCAPs from public datasets (CIC-IDS-2017,
CSE-CIC-IDS2018, CIC-IoT-2023) plus a self-collected capture through the SAME flow-assembly and
78-feature computation code the live device runs (imported from the parallel `services/flowextract/`
phase, not reimplemented), harmonizing each dataset's native label taxonomy onto 7 target attack
classes. Three training scripts (one per algorithm) consume the harmonized data and register each
trained model into the `model_package` SQLite table via a small `ModelRegistry` helper, which also
handles activation/rollback (FR-12.5) and feature-schema compatibility checking (FR-12.4). An
evaluation script computes detection metrics and a cross-dataset generalization matrix script fills
in the spec's Table 5.6 template from real experiments.

**Tech Stack:** Python 3.11+, `scikit-learn`, `xgboost`, `pandas`, `NumPy`, `imbalanced-learn`,
`joblib`, `Scapy`, stdlib `sqlite3`/`hashlib`/`json`/`csv`/`argparse`, `pytest`.

## Global Constraints

- Python 3.11+ (spec Table: Technology Stack). All timestamps are UTC ISO 8601 strings produced
  only via `common.schemas.utc_now_iso()` — this plan's code never calls `datetime.now()` directly
  (the `model_package.deployed_at` column is populated by its own `DEFAULT (strftime(...))` clause
  in `common/db/schema.sql`, so this plan's `ModelRegistry` does not need to generate that timestamp
  itself).
- **Table ownership (per the master roadmap's cross-cutting rules):** this phase is the only phase
  that writes to `model_package` — every other phase's loading code only reads it, filtered
  `WHERE is_active = 1`. This plan never writes to `calibration_state` (a different, parallel phase
  computes per-network threshold calibration against the Isolation Forest this plan produces — this
  plan's job ends at producing a trained, packaged `IFOREST` model). Reads of any other table are
  unrestricted but this plan does not need them.
- **Flow-extraction dependency (FR-12.1, NFR-19) — flagged parallel-phase integration point:** this
  plan never reimplements flow assembly or 78-feature computation. It imports
  `compute_features_from_pcap` from `services.flowextract.features` (a module built by a different,
  concurrently-planned phase) and reads that module's `FEATURE_NAMES` / `FEATURE_SCHEMA_VERSION`
  constants. That phase has not landed yet at the time this plan is written, so every module that
  needs these falls back to a locally-defined placeholder (Task 2's `FALLBACK_FEATURE_NAMES` /
  `FALLBACK_EXTRACTOR_VERSION`) wrapped in a `try/except ImportError`, so the pipeline is fully
  testable standalone. **ASSUMPTION TO REVISIT:** once `services/flowextract/features.py` exists,
  confirm its function/constant names match exactly (a one-line adjustment to the `try/except` import
  lines in Task 2 and Task 8 if not) and delete reliance on the fallback for real training runs.
- **XGBoost security requirement (spec Section 6.6.2):** XGBoost models are saved in native XGBoost
  JSON format via `model.save_model(path)`, **never** via `pickle.dump`/`pickle.load` or `joblib`,
  because pickle/joblib deserialization can execute arbitrary code — unacceptable for a model file an
  admin might later swap onto the live device. scikit-learn models (`IsolationForest`,
  `RandomForestClassifier`) are saved via `joblib`. Task 3 includes an explicit test asserting
  `pickle.dump` is never called for the XGB path.
- **FR-12.4 (schema-compatibility gate):** every model package records `feature_list_hash` (SHA-256
  of the ordered feature-name list + extractor version) and `extractor_version` at packaging time
  (Task 2's `feature_list_hash()`); Task 5's `verify_compatible()` is the helper the live device's
  loading code (built by other phases) is expected to call before marking a loaded model usable.
  This plan does not enforce the check on the live device — it only provides the data and the
  helper function.
- **FR-12.5 / NFR-17 (additive rollback, no traffic interruption):** `model_package` rows are never
  deleted or overwritten by this plan. `ModelRegistry.activate()` only flips `is_active`
  (old row of the same `model_type` → 0, new row → 1); `ModelRegistry.rollback()` reactivates the
  previously-active row. New rows are inserted with `is_active = 0` by default — promoting a newly
  trained model to active is a separate, explicit call (`ModelRegistry.activate(model_id)` or the
  `training/promote_model.py` CLI from Task 4), never automatic at registration time. The live
  device's model-loading code (built by other phases) is documented, not implemented, here as
  re-checking `is_active` periodically rather than requiring a service restart.
- **Public datasets' own pre-computed flow/feature files are never used directly** — only their raw
  PCAPs plus their original per-flow label files are read, because the public datasets' own flow
  construction/labeling has known errors, and a different feature pipeline for training vs.
  inference would break generalization (design note from the source report, Task 8).
- **Class imbalance (Task 10 only, not Task 9's unsupervised Isolation Forest):** this plan uses
  `imbalanced-learn`'s `RandomUnderSampler`, not `SMOTE` — several of the 78 features are
  small-integer counts/ratios (packet counts, flag counts) where SMOTE's linear interpolation
  between neighbors can produce physically implausible synthetic flows (fractional packet counts);
  undersampling the majority class(es) preserves only real observed flows. This choice applies to
  both Task 10 (Random Forest) and Task 11 (XGBoost).
- **Config alignment (not enforced in code, documented only):** Task 9's `train_iforest.py` CLI
  defaults `n_estimators=100`, `max_samples=256` match `anomaly.n_estimators` / `anomaly.subsample_size`
  in `common/config_schema.py` (Phase 1) — both are accepted as tunable function/CLI arguments, never
  hardcoded, so an operator retraining with different values still produces a model whose metadata
  records what was actually used.
- **Testing:** every `ModelRegistry`/compatibility test uses `common.db.migrate.connect(":memory:")`.
  Dataset-builder/feature-harmonization tests use a small local fixture function passed as
  `feature_fn` instead of downloading real multi-GB public datasets — true end-to-end testing against
  real datasets is a manual/CI-separate step, not part of this plan's unit test suite. All
  `IsolationForest`/`RandomForestClassifier`/`XGBClassifier` tests train on small synthetic NumPy
  arrays (tens of rows, single-digit tree counts) to keep the suite fast.

---

## File Structure

```
training/
  __init__.py
  feature_schema.py            # FALLBACK_FEATURE_NAMES/VERSION, get_feature_names(),
                                #   get_extractor_version(), feature_list_hash()
  packaging.py                  # save_model()/load_model() -- joblib for IFOREST/RF, native
                                 #   XGBoost JSON for XGB, never pickle
  dataset_builder/
    __init__.py
    label_mapper.py              # TARGET_CLASSES, per-dataset native-label mapping tables,
                                  #   map_label()
    flow_label_matcher.py          # match_flow_to_label(): 5-tuple + timestamp matching
    builder.py                      # build_dataset(), records_to_dataframe() -- imports
                                     #   services.flowextract.features (flagged integration point)
  train_iforest.py                   # Layer 2 Isolation Forest training + registration
  train_rf.py                         # Layer 3 Random Forest training + registration
  train_xgb.py                         # Layer 3 XGBoost training + registration
  evaluate.py                          # classification_metrics(), iforest_auprc(),
                                        #   write_suricata_comparison_csv() (NFR-11)
  cross_dataset_matrix.py                # run_cross_dataset_matrix() (spec Table 5.6)
  promote_model.py                        # CLI: activate/rollback a model_package row
  reports/
    .gitkeep
models/
  __init__.py
  registry.py                  # ModelRegistry: register/activate/load/rollback/update_metrics
  compatibility.py               # verify_compatible() (FR-12.4)
  artifacts/
    .gitkeep
tests/
  unit/
    test_feature_schema.py
    test_packaging.py
    test_model_registry.py
    test_model_compatibility.py
    test_label_mapper.py
    test_flow_label_matcher.py
    test_dataset_builder.py
    test_train_iforest.py
    test_train_rf.py
    test_train_xgb.py
    test_evaluate.py
    test_cross_dataset_matrix.py
```

---

## Task 1: Project scaffolding for `training/` and `models/`

**Files:**
- Modify: `requirements.txt` (append training-pipeline dependencies)
- Create: `training/__init__.py`
- Create: `training/dataset_builder/__init__.py`
- Create: `training/reports/.gitkeep`
- Create: `models/__init__.py`
- Create: `models/artifacts/.gitkeep`
- Modify: `.gitignore` (ignore generated model/report artifacts)

**Interfaces:**
- Consumes: nothing (first task in this plan).
- Produces: an importable `training`/`models` package layout every later task in this plan assumes
  already exists.

- [ ] **Step 1: Append training-pipeline dependencies to `requirements.txt`**

Add these lines to the existing `requirements.txt` (created by the common-foundations phase):
```
scikit-learn>=1.3,<2.0
xgboost>=2.0,<3.0
pandas>=2.0,<3.0
numpy>=1.24,<2.0
imbalanced-learn>=0.11,<1.0
joblib>=1.3,<2.0
scapy>=2.5,<3.0
```

- [ ] **Step 2: Append generated-artifact ignores to `.gitignore`**

Add these lines to the existing `.gitignore`:
```
models/artifacts/*.joblib
models/artifacts/*.json
training/reports/*.csv
training/reports/*.json
```

- [ ] **Step 3: Create package markers and placeholder directories**

`training/__init__.py`:
```python
```

`training/dataset_builder/__init__.py`:
```python
```

`models/__init__.py`:
```python
```

`training/reports/.gitkeep`:
```
```

`models/artifacts/.gitkeep`:
```
```

- [ ] **Step 4: Install dependencies**

Run:
```bash
.venv/Scripts/pip install -r requirements.txt
```
Expected: packages install without error.

- [ ] **Step 5: Verify all new dependencies import cleanly**

Run:
```bash
.venv/Scripts/python -c "import sklearn, xgboost, pandas, numpy, imblearn, joblib, scapy; print('ok')"
```
Expected: `ok`

- [ ] **Step 6: Commit**

```bash
git add requirements.txt .gitignore training/__init__.py training/dataset_builder/__init__.py training/reports/.gitkeep models/__init__.py models/artifacts/.gitkeep
git commit -m "chore: scaffold training/ and models/ packages for the offline training pipeline"
```

---

## Task 2: Feature-name list and extractor-version resolution (`training/feature_schema.py`)

**Files:**
- Create: `training/feature_schema.py`
- Test: `tests/unit/test_feature_schema.py`

**Interfaces:**
- Consumes: `common.schemas.FEATURE_COUNT` (Phase 1).
- Produces: `FALLBACK_FEATURE_NAMES: list[str]`, `FALLBACK_EXTRACTOR_VERSION: str`,
  `get_feature_names() -> list[str]`, `get_extractor_version() -> str`,
  `feature_list_hash(feature_names: list[str], extractor_version: str) -> str`. Every later task in
  this plan that needs the ordered feature-name list or the extractor version calls these two
  getters rather than hardcoding either.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_feature_schema.py
from common.schemas import FEATURE_COUNT

from training.feature_schema import (
    FALLBACK_EXTRACTOR_VERSION,
    FALLBACK_FEATURE_NAMES,
    feature_list_hash,
    get_extractor_version,
    get_feature_names,
)


def test_fallback_feature_names_length_matches_schema():
    assert len(FALLBACK_FEATURE_NAMES) == FEATURE_COUNT
    assert len(set(FALLBACK_FEATURE_NAMES)) == FEATURE_COUNT  # no duplicates


def test_get_feature_names_falls_back_when_flowextract_not_importable():
    # services.flowextract does not exist yet in this repo -- confirms the fallback path works.
    assert get_feature_names() == FALLBACK_FEATURE_NAMES


def test_get_extractor_version_falls_back_when_flowextract_not_importable():
    assert get_extractor_version() == FALLBACK_EXTRACTOR_VERSION


def test_feature_list_hash_is_deterministic():
    names = ["a", "b", "c"]
    assert feature_list_hash(names, "v1") == feature_list_hash(names, "v1")


def test_feature_list_hash_changes_when_feature_list_changes():
    original = ["a", "b", "c"]
    changed = ["a", "b", "c", "d"]
    assert feature_list_hash(original, "v1") != feature_list_hash(changed, "v1")


def test_feature_list_hash_changes_when_extractor_version_changes():
    names = ["a", "b", "c"]
    assert feature_list_hash(names, "v1") != feature_list_hash(names, "v2")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_feature_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.feature_schema'`

- [ ] **Step 3: Write `training/feature_schema.py`**

```python
"""Feature-name list and extractor-version resolution for the offline training pipeline.

INTEGRATION POINT (flagged, parallel phase): the canonical 78-feature name list and the
extractor-version string are owned by the parallel flow-extraction phase, expected at
`services.flowextract.features.FEATURE_NAMES` / `services.flowextract.features.FEATURE_SCHEMA_VERSION`.
That phase has not landed yet, so this module falls back to a locally-defined placeholder list so
the training pipeline is fully testable standalone. ASSUMPTION TO REVISIT: once
`services/flowextract/features.py` exists, confirm its exported names match exactly (a one-line
fix to the try/except below if not) and stop relying on the fallback for real training runs.
"""
from __future__ import annotations

import hashlib
import json

from common.schemas import FEATURE_COUNT

try:
    from services.flowextract.features import FEATURE_NAMES as _EXTRACTOR_FEATURE_NAMES
    from services.flowextract.features import FEATURE_SCHEMA_VERSION as _EXTRACTOR_VERSION
except ImportError:
    _EXTRACTOR_FEATURE_NAMES = None
    _EXTRACTOR_VERSION = None

FALLBACK_EXTRACTOR_VERSION = "unknown-pre-flowextract"

FALLBACK_FEATURE_NAMES = (
    ["duration_s", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes"]
    + [f"fwd_pkt_len_{stat}" for stat in ("min", "max", "mean", "std")]
    + [f"bwd_pkt_len_{stat}" for stat in ("min", "max", "mean", "std")]
    + ["flow_bytes_per_s", "flow_packets_per_s"]
    + [f"flow_iat_{stat}" for stat in ("mean", "std", "min", "max")]
    + [f"fwd_iat_{stat}" for stat in ("total", "mean", "std", "min", "max")]
    + [f"bwd_iat_{stat}" for stat in ("total", "mean", "std", "min", "max")]
    + ["fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags"]
    + ["fwd_header_len", "bwd_header_len"]
    + ["fwd_packets_per_s", "bwd_packets_per_s"]
    + [f"pkt_len_{stat}" for stat in ("min", "max", "mean", "std", "var")]
    + [f"flag_count_{f}" for f in ("fin", "syn", "rst", "psh", "ack", "urg", "cwe", "ece")]
    + ["down_up_ratio", "avg_pkt_size", "avg_fwd_segment_size", "avg_bwd_segment_size"]
    + ["fwd_avg_bytes_bulk", "fwd_avg_pkts_bulk", "fwd_avg_bulk_rate"]
    + ["bwd_avg_bytes_bulk", "bwd_avg_pkts_bulk", "bwd_avg_bulk_rate"]
    + ["subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes"]
    + ["init_win_bytes_fwd", "init_win_bytes_bwd", "act_data_pkt_fwd", "min_seg_size_fwd"]
    + [f"active_{stat}" for stat in ("mean", "std", "max", "min")]
    + [f"idle_{stat}" for stat in ("mean", "std", "max", "min")]
    + ["ja3_hash_present", "sni_entropy"]
)

assert len(FALLBACK_FEATURE_NAMES) == FEATURE_COUNT, (
    f"FALLBACK_FEATURE_NAMES has {len(FALLBACK_FEATURE_NAMES)} entries, expected {FEATURE_COUNT}"
)


def get_feature_names() -> list:
    """Ordered 78-feature name list used by the live flow extractor; falls back to
    FALLBACK_FEATURE_NAMES when services.flowextract is not yet importable."""
    if _EXTRACTOR_FEATURE_NAMES is not None:
        return list(_EXTRACTOR_FEATURE_NAMES)
    return list(FALLBACK_FEATURE_NAMES)


def get_extractor_version() -> str:
    """Version string reported by the live flow extractor; falls back to
    FALLBACK_EXTRACTOR_VERSION when services.flowextract is not yet importable."""
    if _EXTRACTOR_VERSION is not None:
        return _EXTRACTOR_VERSION
    return FALLBACK_EXTRACTOR_VERSION


def feature_list_hash(feature_names: list, extractor_version: str) -> str:
    """Deterministic SHA-256 hash of an ordered feature-name list plus the extractor version that
    produced it (FR-12.4). Order matters -- do not sort feature_names before hashing."""
    payload = json.dumps(
        {"features": list(feature_names), "extractor_version": extractor_version},
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_feature_schema.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add training/feature_schema.py tests/unit/test_feature_schema.py
git commit -m "feat: add feature-name/extractor-version resolution and feature_list_hash"
```

---

## Task 3: Model file packaging — never pickle for XGBoost (`training/packaging.py`)

**Files:**
- Create: `training/packaging.py`
- Test: `tests/unit/test_packaging.py`

**Interfaces:**
- Consumes: nothing beyond stdlib + `joblib`.
- Produces: `save_model(model, model_type: str, version: str, out_dir: str) -> str` (returns the
  saved file path), `load_model(model_type: str, file_path: str)`. Tasks 9-11's training scripts
  call `save_model()`; `training/evaluate.py` (Task 12) calls `load_model()`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_packaging.py
import inspect
import json
import pickle

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

import training.packaging as packaging_module
from training.packaging import load_model, save_model


def test_sklearn_model_saved_via_joblib_and_reloadable(tmp_path):
    model = IsolationForest(n_estimators=5, max_samples=8, random_state=0)
    model.fit(np.zeros((20, 3)))

    file_path = save_model(model, "IFOREST", "0.1.0", str(tmp_path))

    assert file_path.endswith(".joblib")
    loaded = joblib.load(file_path)
    assert isinstance(loaded, IsolationForest)

    reloaded_via_api = load_model("IFOREST", file_path)
    assert isinstance(reloaded_via_api, IsolationForest)


def test_xgb_model_saved_as_native_json_never_pickled(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("pickle.dump/dumps must never be called for XGB models")

    monkeypatch.setattr(pickle, "dump", _boom)
    monkeypatch.setattr(pickle, "dumps", _boom)

    X = np.array([[0, 0], [1, 1], [0, 1], [1, 0]])
    y = np.array([0, 1, 0, 1])
    model = XGBClassifier(n_estimators=2, max_depth=2)
    model.fit(X, y)

    file_path = save_model(model, "XGB", "0.1.0", str(tmp_path))

    assert file_path.endswith(".json")
    with open(file_path, "r", encoding="utf-8") as f:
        payload = json.load(f)  # must be valid JSON text, not a pickle byte-stream
    assert isinstance(payload, dict)

    reloaded = load_model("XGB", file_path)
    preds = reloaded.predict(X)
    assert len(preds) == len(y)


def test_packaging_module_source_never_imports_or_calls_pickle():
    source = inspect.getsource(packaging_module)
    assert "import pickle" not in source
    assert "pickle.dump" not in source
    assert "pickle.load" not in source


def test_save_model_rejects_unknown_model_type(tmp_path):
    with pytest.raises(ValueError):
        save_model(object(), "NOT-A-TYPE", "0.1.0", str(tmp_path))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_packaging.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.packaging'`

- [ ] **Step 3: Write `training/packaging.py`**

```python
"""Model-file packaging. XGBoost models are saved in native XGBoost JSON format, never via
pickle or joblib (spec Section 6.6.2) -- pickle/joblib deserialization can execute arbitrary
code, which is unacceptable for a model file an admin might later swap onto the live device.
scikit-learn models (IsolationForest, RandomForestClassifier) are saved via joblib."""
from __future__ import annotations

from pathlib import Path

import joblib

_EXTENSIONS = {"IFOREST": "joblib", "RF": "joblib", "XGB": "json"}


def save_model(model, model_type: str, version: str, out_dir: str) -> str:
    """Saves model to a deterministic path under out_dir and returns that path as a string."""
    if model_type not in _EXTENSIONS:
        raise ValueError(f"Unknown model_type: {model_type!r}")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    safe_version = version.replace("/", "_")
    file_path = out_path / f"{model_type.lower()}_{safe_version}.{_EXTENSIONS[model_type]}"

    if model_type == "XGB":
        model.save_model(str(file_path))  # native XGBoost JSON -- never pickle.dump
    else:
        joblib.dump(model, file_path)  # joblib, not pickle, for scikit-learn models

    return str(file_path)


def load_model(model_type: str, file_path: str):
    """Loads a model previously saved by save_model()."""
    if model_type not in _EXTENSIONS:
        raise ValueError(f"Unknown model_type: {model_type!r}")

    if model_type == "XGB":
        from xgboost import XGBClassifier

        model = XGBClassifier()
        model.load_model(file_path)
        return model

    return joblib.load(file_path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_packaging.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add training/packaging.py tests/unit/test_packaging.py
git commit -m "feat: add model packaging (joblib for sklearn, native JSON for XGBoost, never pickle)"
```

---

## Task 4: `ModelRegistry` (`models/registry.py`)

**Files:**
- Create: `models/registry.py`
- Create: `training/promote_model.py`
- Test: `tests/unit/test_model_registry.py`

**Interfaces:**
- Consumes: `common.db.migrate.connect` (Phase 1), `training.feature_schema.feature_list_hash`
  (Task 2).
- Produces: `ModelRegistry(conn)` with `register(model_type, version, file_path, feature_list,
  extractor_version, class_list=None, training_data=None, metrics=None) -> int`,
  `activate(model_id: int) -> None`, `load(model_type: str) -> dict | None`,
  `rollback(model_type: str) -> None`, `update_metrics(model_id: int, metrics: dict) -> None`.
  Tasks 9-11 call `register()`; Task 12 calls `update_metrics()`; `training/promote_model.py` calls
  `activate()`/`rollback()`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_model_registry.py
import json

import pytest

from common.db.migrate import connect
from models.registry import ModelRegistry


def test_register_returns_an_integer_model_id():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)

    model_id = registry.register(
        model_type="RF",
        version="0.1.0",
        file_path="models/artifacts/rf_0.1.0.joblib",
        feature_list=["f1", "f2"],
        extractor_version="flowextract-1.0",
        class_list=["Benign", "DoS/DDoS"],
        training_data={"dataset": "CIC-IDS-2017", "n_samples": 100},
        metrics=None,
    )

    assert isinstance(model_id, int)


def test_new_model_package_rows_default_to_inactive():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)

    model_id = registry.register("RF", "0.1.0", "p1", ["f1"], "ex-1.0")

    row = conn.execute(
        "SELECT is_active FROM model_package WHERE model_id = ?", (model_id,)
    ).fetchone()
    assert row[0] == 0


def test_activate_deactivates_previous_model_of_same_type():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    v1 = registry.register("RF", "0.1.0", "p1", ["f1"], "ex-1.0")
    v2 = registry.register("RF", "0.2.0", "p2", ["f1"], "ex-1.0")

    registry.activate(v1)
    registry.activate(v2)

    is_active_v1 = conn.execute(
        "SELECT is_active FROM model_package WHERE model_id = ?", (v1,)
    ).fetchone()[0]
    is_active_v2 = conn.execute(
        "SELECT is_active FROM model_package WHERE model_id = ?", (v2,)
    ).fetchone()[0]
    assert is_active_v1 == 0
    assert is_active_v2 == 1


def test_activate_does_not_affect_a_different_model_type():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    rf_id = registry.register("RF", "0.1.0", "p1", ["f1"], "ex-1.0")
    xgb_id = registry.register("XGB", "0.1.0", "p2", ["f1"], "ex-1.0")

    registry.activate(rf_id)
    registry.activate(xgb_id)

    assert registry.load("RF")["model_id"] == rf_id
    assert registry.load("XGB")["model_id"] == xgb_id


def test_load_returns_none_when_no_active_model_of_that_type():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    registry.register("RF", "0.1.0", "p1", ["f1"], "ex-1.0")  # never activated

    assert registry.load("RF") is None


def test_load_deserializes_json_columns():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    model_id = registry.register(
        "RF", "0.1.0", "p1", ["f1"], "ex-1.0",
        class_list=["Benign", "DoS/DDoS"],
        training_data={"n_samples": 50},
        metrics={"f1_macro": 0.8},
    )
    registry.activate(model_id)

    loaded = registry.load("RF")
    assert loaded["class_list"] == ["Benign", "DoS/DDoS"]
    assert loaded["training_data"] == {"n_samples": 50}
    assert loaded["metrics"] == {"f1_macro": 0.8}
    assert loaded["is_active"] is True


def test_rollback_reactivates_previous_model():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    v1 = registry.register("XGB", "0.1.0", "p1", ["f1"], "ex-1.0")
    v2 = registry.register("XGB", "0.2.0", "p2", ["f1"], "ex-1.0")
    registry.activate(v1)
    registry.activate(v2)

    registry.rollback("XGB")

    assert registry.load("XGB")["model_id"] == v1


def test_rollback_raises_lookuperror_when_no_previous_model_exists():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    v1 = registry.register("RF", "0.1.0", "p1", ["f1"], "ex-1.0")
    registry.activate(v1)

    with pytest.raises(LookupError):
        registry.rollback("RF")


def test_update_metrics_writes_json_metrics_column():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)
    model_id = registry.register("IFOREST", "0.1.0", "p1", ["f1"], "ex-1.0")

    registry.update_metrics(model_id, {"auprc": 0.93})

    row = conn.execute(
        "SELECT metrics FROM model_package WHERE model_id = ?", (model_id,)
    ).fetchone()
    assert json.loads(row[0]) == {"auprc": 0.93}


def test_update_metrics_raises_keyerror_for_unknown_model_id():
    conn = connect(":memory:")
    registry = ModelRegistry(conn)

    with pytest.raises(KeyError):
        registry.update_metrics(9999, {"auprc": 0.5})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_model_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'models.registry'`

- [ ] **Step 3: Write `models/registry.py`**

```python
"""ModelRegistry: owns every write to model_package (FR-12.3, FR-12.5). Promoting a newly
registered model to active is always a separate, explicit call -- rows are inserted with
is_active = 0 and are never deleted, so rollback is just flipping the flag back.

Note on rollback(): the model_package schema (owned by Phase 1) has no 'deactivated_at' column,
only 'deployed_at' (set once, at registration time, by the table's own DEFAULT clause). This
registry's activate()/register() pattern is always register-then-activate per model, so among a
model_type's inactive rows, the one with the most recent deployed_at is the one that was active
immediately before the current one and is therefore the correct one-step rollback target."""
from __future__ import annotations

import json
import sqlite3
from typing import Optional

from training.feature_schema import feature_list_hash


class ModelRegistry:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def register(
        self,
        model_type: str,
        version: str,
        file_path: str,
        feature_list: list,
        extractor_version: str,
        class_list: Optional[list] = None,
        training_data: Optional[dict] = None,
        metrics: Optional[dict] = None,
    ) -> int:
        f_hash = feature_list_hash(feature_list, extractor_version)
        cursor = self._conn.execute(
            """INSERT INTO model_package
               (model_type, version, file_path, feature_list_hash, extractor_version,
                class_list, training_data, metrics, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                model_type,
                version,
                file_path,
                f_hash,
                extractor_version,
                json.dumps(class_list) if class_list is not None else None,
                json.dumps(training_data) if training_data is not None else None,
                json.dumps(metrics) if metrics is not None else None,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def activate(self, model_id: int) -> None:
        row = self._conn.execute(
            "SELECT model_type FROM model_package WHERE model_id = ?", (model_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"No model_package row with model_id={model_id}")
        model_type = row[0]

        self._conn.execute(
            "UPDATE model_package SET is_active = 0 WHERE model_type = ? AND model_id != ?",
            (model_type, model_id),
        )
        self._conn.execute(
            "UPDATE model_package SET is_active = 1 WHERE model_id = ?", (model_id,)
        )
        self._conn.commit()

    def load(self, model_type: str) -> Optional[dict]:
        row = self._conn.execute(
            """SELECT model_id, model_type, version, file_path, feature_list_hash,
                      extractor_version, class_list, training_data, metrics, is_active,
                      deployed_at
               FROM model_package WHERE model_type = ? AND is_active = 1""",
            (model_type,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def rollback(self, model_type: str) -> None:
        previous = self._conn.execute(
            """SELECT model_id FROM model_package
               WHERE model_type = ? AND is_active = 0
               ORDER BY deployed_at DESC, model_id DESC LIMIT 1""",
            (model_type,),
        ).fetchone()
        if previous is None:
            raise LookupError(f"No previous {model_type} model to roll back to")
        self.activate(previous[0])

    def update_metrics(self, model_id: int, metrics: dict) -> None:
        row = self._conn.execute(
            "SELECT model_id FROM model_package WHERE model_id = ?", (model_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"No model_package row with model_id={model_id}")
        self._conn.execute(
            "UPDATE model_package SET metrics = ? WHERE model_id = ?",
            (json.dumps(metrics), model_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_dict(row) -> dict:
        (
            model_id, model_type, version, file_path, feature_list_hash_value,
            extractor_version, class_list, training_data, metrics, is_active, deployed_at,
        ) = row
        return {
            "model_id": model_id,
            "model_type": model_type,
            "version": version,
            "file_path": file_path,
            "feature_list_hash": feature_list_hash_value,
            "extractor_version": extractor_version,
            "class_list": json.loads(class_list) if class_list else None,
            "training_data": json.loads(training_data) if training_data else None,
            "metrics": json.loads(metrics) if metrics else None,
            "is_active": bool(is_active),
            "deployed_at": deployed_at,
        }
```

- [ ] **Step 4: Write `training/promote_model.py`**

```python
"""CLI helper to promote a newly trained model to active, or roll back to the previous one.
This is the operator-facing entry point for FR-12.5 -- registration (Tasks 9-11) never activates
a model automatically.

Usage:
    python -m training.promote_model activate <db_path> <model_id>
    python -m training.promote_model rollback <db_path> <model_type>
"""
from __future__ import annotations

import argparse

from common.db.migrate import connect
from models.registry import ModelRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote or roll back a trained model.")
    parser.add_argument("action", choices=["activate", "rollback"])
    parser.add_argument("db_path")
    parser.add_argument("target", help="model_id for activate, model_type for rollback")
    args = parser.parse_args()

    conn = connect(args.db_path)
    registry = ModelRegistry(conn)
    if args.action == "activate":
        registry.activate(int(args.target))
        print(f"Activated model_id={args.target}")
    else:
        registry.rollback(args.target)
        print(f"Rolled back model_type={args.target} to its previous version")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_model_registry.py -v`
Expected: 10 passed

- [ ] **Step 6: Commit**

```bash
git add models/registry.py training/promote_model.py tests/unit/test_model_registry.py
git commit -m "feat: add ModelRegistry (register/activate/load/rollback/update_metrics)"
```

---

## Task 5: Feature-schema compatibility gate (`models/compatibility.py`)

**Files:**
- Create: `models/compatibility.py`
- Test: `tests/unit/test_model_compatibility.py`

**Interfaces:**
- Consumes: `training.feature_schema.feature_list_hash` (Task 2), `ModelRegistry.load()`'s dict
  shape (Task 4).
- Produces: `verify_compatible(model_package_row: dict, current_extractor_version: str,
  current_feature_list: list) -> bool`. The live device's model-loading code (built by other
  phases) is expected to call this before marking a loaded model usable (FR-12.4).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_model_compatibility.py
from training.feature_schema import feature_list_hash
from models.compatibility import verify_compatible


def test_verify_compatible_true_when_everything_matches():
    feature_list = ["f1", "f2", "f3"]
    extractor_version = "flowextract-1.0"
    row = {
        "feature_list_hash": feature_list_hash(feature_list, extractor_version),
        "extractor_version": extractor_version,
    }

    assert verify_compatible(row, extractor_version, feature_list) is True


def test_verify_compatible_false_when_extractor_version_differs():
    feature_list = ["f1", "f2", "f3"]
    row = {
        "feature_list_hash": feature_list_hash(feature_list, "flowextract-1.0"),
        "extractor_version": "flowextract-1.0",
    }

    assert verify_compatible(row, "flowextract-2.0", feature_list) is False


def test_verify_compatible_false_when_feature_list_changed():
    extractor_version = "flowextract-1.0"
    original = ["f1", "f2", "f3"]
    row = {
        "feature_list_hash": feature_list_hash(original, extractor_version),
        "extractor_version": extractor_version,
    }
    changed_list = ["f1", "f2", "f3", "f4"]

    assert verify_compatible(row, extractor_version, changed_list) is False


def test_verify_compatible_false_when_feature_order_changed():
    extractor_version = "flowextract-1.0"
    original = ["f1", "f2", "f3"]
    row = {
        "feature_list_hash": feature_list_hash(original, extractor_version),
        "extractor_version": extractor_version,
    }
    reordered = ["f2", "f1", "f3"]

    assert verify_compatible(row, extractor_version, reordered) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_model_compatibility.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'models.compatibility'`

- [ ] **Step 3: Write `models/compatibility.py`**

```python
"""FR-12.4: refuse to treat a model as loadable/usable when its feature schema does not match
the current flow extractor. This plan only provides the check; the live device's loading code
(built by other phases) is expected to call verify_compatible() before marking a model usable and
to refuse activation/use otherwise."""
from __future__ import annotations

from training.feature_schema import feature_list_hash


def verify_compatible(
    model_package_row: dict, current_extractor_version: str, current_feature_list: list
) -> bool:
    """Returns True only if model_package_row's stored feature_list_hash/extractor_version
    exactly match what the current flow extractor would produce today."""
    if model_package_row.get("extractor_version") != current_extractor_version:
        return False
    expected_hash = feature_list_hash(current_feature_list, current_extractor_version)
    return model_package_row.get("feature_list_hash") == expected_hash
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_model_compatibility.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add models/compatibility.py tests/unit/test_model_compatibility.py
git commit -m "feat: add FR-12.4 feature-schema compatibility gate (verify_compatible)"
```

---

## Task 6: Per-dataset label mapping onto the 7 target classes (`training/dataset_builder/label_mapper.py`)

**Files:**
- Create: `training/dataset_builder/label_mapper.py`
- Test: `tests/unit/test_label_mapper.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `TARGET_CLASSES: list[str]` (the 7 classes), `map_label(dataset_name: str,
  native_label: str) -> str`. Task 8's dataset builder calls `map_label()` to harmonize every
  matched flow's original label onto one of `TARGET_CLASSES`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_label_mapper.py
import pytest

from training.dataset_builder.label_mapper import (
    TARGET_CLASSES,
    _DATASET_MAPS,
    map_label,
)


def test_map_label_cic_ids_2017_benign():
    assert map_label("CIC-IDS-2017", "BENIGN") == "Benign"


def test_map_label_cic_ids_2017_portscan_maps_to_reconnaissance():
    assert map_label("CIC-IDS-2017", "PortScan") == "Reconnaissance"


def test_map_label_cic_ids_2017_patator_variants_map_to_brute_force():
    assert map_label("CIC-IDS-2017", "FTP-Patator") == "Brute Force"
    assert map_label("CIC-IDS-2017", "SSH-Patator") == "Brute Force"


def test_map_label_cic_ids_2017_dos_variants_map_to_dos_ddos():
    for native in ("DoS slowloris", "DoS Slowhttptest", "DoS Hulk", "DoS GoldenEye", "DDoS"):
        assert map_label("CIC-IDS-2017", native) == "DoS/DDoS"


def test_map_label_cse_cic_ids2018_bruteforce_variants():
    assert map_label("CSE-CIC-IDS2018", "FTP-BruteForce") == "Brute Force"
    assert map_label("CSE-CIC-IDS2018", "SSH-Bruteforce") == "Brute Force"


def test_map_label_cic_iot_2023_categories():
    assert map_label("CIC-IoT-2023", "Mirai") == "Botnet/C2"
    assert map_label("CIC-IoT-2023", "Spoofing") == "Spoofing"
    assert map_label("CIC-IoT-2023", "Recon") == "Reconnaissance"


def test_map_label_self_collected_tool_labels():
    assert map_label("SELF-COLLECTED", "nmap") == "Reconnaissance"
    assert map_label("SELF-COLLECTED", "hydra") == "Brute Force"
    assert map_label("SELF-COLLECTED", "hping3") == "DoS/DDoS"
    assert map_label("SELF-COLLECTED", "arpspoof") == "Spoofing"
    assert map_label("SELF-COLLECTED", "dnsspoof") == "Spoofing"
    assert map_label("SELF-COLLECTED", "benign") == "Benign"


def test_map_label_unknown_dataset_raises_keyerror():
    with pytest.raises(KeyError):
        map_label("NOT-A-REAL-DATASET", "BENIGN")


def test_map_label_unknown_native_label_raises_valueerror():
    with pytest.raises(ValueError):
        map_label("CIC-IDS-2017", "Not A Real Label")


def test_every_mapped_value_is_a_target_class():
    for table in _DATASET_MAPS.values():
        for mapped in table.values():
            assert mapped in TARGET_CLASSES


def test_target_classes_has_exactly_seven_entries():
    assert len(TARGET_CLASSES) == 7
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_label_mapper.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.dataset_builder.label_mapper'`

- [ ] **Step 3: Write `training/dataset_builder/label_mapper.py`**

```python
"""Per-dataset native-label -> 7-class target taxonomy mapping. Each dataset's own flow/label
files use a different label taxonomy; this module is the single place that harmonizes them onto
TARGET_CLASSES so a model trained on one dataset's labels is directly comparable to another's.

Gaps are documented, not hidden: CIC-IDS-2017 and CSE-CIC-IDS2018 have no native spoofing
attack, so neither mapping table produces 'Spoofing' -- only CIC-IoT-2023 and the self-collected
dataset do. The self-collected dataset (captured with nmap/hydra/hping3/arpspoof/dnsspoof per the
source report) has no Botnet/C2 or Infiltration/Lateral Movement tool in its toolkit, so those two
classes are absent from _SELF_COLLECTED until the team adds a tool that produces them."""
from __future__ import annotations

TARGET_CLASSES = [
    "Benign",
    "Reconnaissance",
    "Brute Force",
    "DoS/DDoS",
    "Botnet/C2",
    "Spoofing",
    "Infiltration/Lateral Movement",
]

_CIC_IDS_2017 = {
    "BENIGN": "Benign",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Web Attack - Brute Force": "Brute Force",
    "DoS slowloris": "DoS/DDoS",
    "DoS Slowhttptest": "DoS/DDoS",
    "DoS Hulk": "DoS/DDoS",
    "DoS GoldenEye": "DoS/DDoS",
    "DDoS": "DoS/DDoS",
    "Heartbleed": "Infiltration/Lateral Movement",
    "Web Attack - XSS": "Infiltration/Lateral Movement",
    "Web Attack - Sql Injection": "Infiltration/Lateral Movement",
    "Infiltration": "Infiltration/Lateral Movement",
    "Bot": "Botnet/C2",
    "PortScan": "Reconnaissance",
}

_CSE_CIC_IDS2018 = {
    "Benign": "Benign",
    "FTP-BruteForce": "Brute Force",
    "SSH-Bruteforce": "Brute Force",
    "Brute Force -Web": "Brute Force",
    "DoS attacks-Hulk": "DoS/DDoS",
    "DoS attacks-SlowHTTPTest": "DoS/DDoS",
    "DoS attacks-GoldenEye": "DoS/DDoS",
    "DoS attacks-Slowloris": "DoS/DDoS",
    "DDOS attack-HOIC": "DoS/DDoS",
    "DDOS attack-LOIC-UDP": "DoS/DDoS",
    "DDoS attacks-LOIC-HTTP": "DoS/DDoS",
    "Bot": "Botnet/C2",
    "Infilteration": "Infiltration/Lateral Movement",
    "Brute Force -XSS": "Infiltration/Lateral Movement",
    "SQL Injection": "Infiltration/Lateral Movement",
}

_CIC_IOT_2023 = {
    "Benign": "Benign",
    "DDoS": "DoS/DDoS",
    "DoS": "DoS/DDoS",
    "Recon": "Reconnaissance",
    "Brute Force": "Brute Force",
    "Spoofing": "Spoofing",
    "Mirai": "Botnet/C2",
    "Web-Based": "Infiltration/Lateral Movement",
}

_SELF_COLLECTED = {
    "benign": "Benign",
    "nmap": "Reconnaissance",
    "hydra": "Brute Force",
    "hping3": "DoS/DDoS",
    "arpspoof": "Spoofing",
    "dnsspoof": "Spoofing",
}

_DATASET_MAPS = {
    "CIC-IDS-2017": _CIC_IDS_2017,
    "CSE-CIC-IDS2018": _CSE_CIC_IDS2018,
    "CIC-IoT-2023": _CIC_IOT_2023,
    "SELF-COLLECTED": _SELF_COLLECTED,
}


def map_label(dataset_name: str, native_label: str) -> str:
    """Maps one dataset's native label string onto one of TARGET_CLASSES.
    Raises KeyError if dataset_name is unknown, ValueError if native_label has no mapping."""
    if dataset_name not in _DATASET_MAPS:
        raise KeyError(f"Unknown dataset_name: {dataset_name!r}")
    table = _DATASET_MAPS[dataset_name]
    if native_label not in table:
        raise ValueError(f"No label mapping for {dataset_name!r} native label {native_label!r}")
    return table[native_label]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_label_mapper.py -v`
Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add training/dataset_builder/label_mapper.py tests/unit/test_label_mapper.py
git commit -m "feat: add per-dataset label mapping onto the 7 target attack classes"
```

---

## Task 7: Flow-to-original-label matching (`training/dataset_builder/flow_label_matcher.py`)

**Files:**
- Create: `training/dataset_builder/flow_label_matcher.py`
- Test: `tests/unit/test_flow_label_matcher.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `match_flow_to_label(flow: dict, label_records: list[dict], time_tolerance_s: float =
  1.0) -> str | None`. Task 8's dataset builder calls this to re-attach each public dataset's
  original per-flow label to the flow this plan's own flow extractor re-assembled from the raw
  PCAP (FR-12.1's "re-processed through the SAME flow extractor" step needs the labels matched
  back on afterward, since they were computed by a different, unused flow-construction pipeline).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_flow_label_matcher.py
from training.dataset_builder.flow_label_matcher import match_flow_to_label

_LABELS = [
    {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 100.2, "native_label": "BENIGN",
    },
    {
        "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "src_port": 51010, "dst_port": 22,
        "protocol": "TCP", "start_time": 200.1, "native_label": "SSH-Patator",
    },
]


def test_matches_exact_5tuple_within_time_tolerance():
    flow = {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 100.0,
    }
    assert match_flow_to_label(flow, _LABELS) == "BENIGN"


def test_matches_reversed_5tuple():
    flow = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.5", "src_port": 80, "dst_port": 51000,
        "protocol": "TCP", "start_time": 100.3,
    }
    assert match_flow_to_label(flow, _LABELS) == "BENIGN"


def test_returns_none_when_no_5tuple_matches():
    flow = {
        "src_ip": "192.168.9.9", "dst_ip": "10.0.0.1", "src_port": 9999, "dst_port": 80,
        "protocol": "TCP", "start_time": 100.0,
    }
    assert match_flow_to_label(flow, _LABELS) is None


def test_returns_none_when_timestamp_outside_tolerance():
    flow = {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 150.0,  # far outside default 1.0s tolerance
    }
    assert match_flow_to_label(flow, _LABELS) is None


def test_picks_closest_timestamp_when_multiple_candidates_share_5tuple():
    labels_with_duplicate_tuple = _LABELS + [
        {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
            "protocol": "TCP", "start_time": 100.05, "native_label": "PortScan",
        }
    ]
    flow = {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 100.0,
    }
    # 100.05 is closer to 100.0 than 100.2 is -- the closer candidate wins
    assert match_flow_to_label(flow, labels_with_duplicate_tuple) == "PortScan"


def test_time_tolerance_is_configurable():
    flow = {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 103.0,
    }
    assert match_flow_to_label(flow, _LABELS, time_tolerance_s=1.0) is None
    assert match_flow_to_label(flow, _LABELS, time_tolerance_s=5.0) == "BENIGN"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_flow_label_matcher.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.dataset_builder.flow_label_matcher'`

- [ ] **Step 3: Write `training/dataset_builder/flow_label_matcher.py`**

```python
"""Matches a flow this plan's flow extractor assembled from a raw PCAP back to the original
dataset's per-flow label, by 5-tuple (forward or reversed, since label-file and extractor
direction conventions may differ) plus a start-time tolerance window."""
from __future__ import annotations

from typing import Optional


def _same_tuple(flow: dict, record: dict) -> bool:
    forward = (
        flow["src_ip"] == record["src_ip"]
        and flow["dst_ip"] == record["dst_ip"]
        and flow["src_port"] == record["src_port"]
        and flow["dst_port"] == record["dst_port"]
        and flow["protocol"] == record["protocol"]
    )
    reverse = (
        flow["src_ip"] == record["dst_ip"]
        and flow["dst_ip"] == record["src_ip"]
        and flow["src_port"] == record["dst_port"]
        and flow["dst_port"] == record["src_port"]
        and flow["protocol"] == record["protocol"]
    )
    return forward or reverse


def match_flow_to_label(
    flow: dict, label_records: list, time_tolerance_s: float = 1.0
) -> Optional[str]:
    """flow and each entry of label_records must have keys src_ip, dst_ip, src_port, dst_port,
    protocol, start_time (epoch float); label_records entries additionally have native_label.
    Returns the native_label of the closest-in-time matching record, or None if none match."""
    best_label = None
    best_delta = None
    for record in label_records:
        if not _same_tuple(flow, record):
            continue
        delta = abs(flow["start_time"] - record["start_time"])
        if delta > time_tolerance_s:
            continue
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best_label = record["native_label"]
    return best_label
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_flow_label_matcher.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add training/dataset_builder/flow_label_matcher.py tests/unit/test_flow_label_matcher.py
git commit -m "feat: add flow-to-original-label 5-tuple/timestamp matcher"
```

---

## Task 8: Dataset builder (`training/dataset_builder/builder.py`)

**Files:**
- Create: `training/dataset_builder/builder.py`
- Test: `tests/unit/test_dataset_builder.py`

**Interfaces:**
- Consumes: `common.schemas.{FEATURE_COUNT, SCHEMA_VERSION, FlowFeatures}` (Phase 1),
  `training.dataset_builder.flow_label_matcher.match_flow_to_label` (Task 7),
  `training.dataset_builder.label_mapper.map_label` (Task 6),
  `training.feature_schema.get_feature_names` (Task 2), and — the flagged parallel-phase
  integration point — `services.flowextract.features.compute_features_from_pcap`.
- Produces: `build_dataset(pcap_path: str, label_records: list[dict], dataset_name: str,
  time_tolerance_s: float = 1.0, feature_fn: Callable[[str], list[dict]] | None = None) ->
  list[dict]`, `records_to_dataframe(records: list[dict]) -> pandas.DataFrame`. Tasks 9-13's
  training/evaluation scripts consume the DataFrame `records_to_dataframe()` produces (one column
  per feature name, plus `label` and `dataset`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dataset_builder.py
import pytest

from common.schemas import FEATURE_COUNT

from training.dataset_builder.builder import build_dataset, records_to_dataframe
import training.dataset_builder.builder as builder_module


def _fixture_feature_fn(pcap_path):
    """Deterministic stand-in for services.flowextract.features.compute_features_from_pcap,
    used so this test suite never depends on the parallel flow-extraction phase landing."""
    return [
        {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
            "protocol": "TCP", "start_time": 100.0, "end_time": 100.5,
            "features": [0.1] * FEATURE_COUNT,
        },
        {
            "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "src_port": 51010, "dst_port": 22,
            "protocol": "TCP", "start_time": 200.0, "end_time": 200.2,
            "features": [0.2] * FEATURE_COUNT,
        },
    ]


_LABELS = [
    {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 51000, "dst_port": 80,
        "protocol": "TCP", "start_time": 100.2, "native_label": "BENIGN",
    },
    {
        "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "src_port": 51010, "dst_port": 22,
        "protocol": "TCP", "start_time": 200.1, "native_label": "SSH-Patator",
    },
]


def test_build_dataset_harmonizes_matched_labels_onto_target_classes():
    records = build_dataset(
        "unused.pcap", _LABELS, "CIC-IDS-2017", feature_fn=_fixture_feature_fn
    )

    assert len(records) == 2
    assert records[0]["label"] == "Benign"
    assert records[1]["label"] == "Brute Force"
    assert records[0]["features"].validate() is True
    assert records[0]["dataset"] == "CIC-IDS-2017"


def test_build_dataset_leaves_label_none_when_no_original_label_matches():
    def _unmatched_feature_fn(pcap_path):
        flows = _fixture_feature_fn(pcap_path)
        flows[0]["src_ip"] = "192.168.9.9"  # won't match any _LABELS record
        return flows

    records = build_dataset(
        "unused.pcap", _LABELS, "CIC-IDS-2017", feature_fn=_unmatched_feature_fn
    )
    assert records[0]["label"] is None


def test_build_dataset_raises_valueerror_on_wrong_feature_vector_length():
    def _bad_feature_fn(pcap_path):
        flows = _fixture_feature_fn(pcap_path)
        flows[0]["features"] = [0.1] * (FEATURE_COUNT - 1)
        return flows

    with pytest.raises(ValueError):
        build_dataset("unused.pcap", _LABELS, "CIC-IDS-2017", feature_fn=_bad_feature_fn)


def test_build_dataset_raises_runtimeerror_without_feature_fn_or_flowextract(monkeypatch):
    monkeypatch.setattr(builder_module, "_compute_features_from_pcap", None)

    with pytest.raises(RuntimeError):
        build_dataset("unused.pcap", _LABELS, "CIC-IDS-2017")


def test_records_to_dataframe_drops_unlabeled_rows_and_has_one_column_per_feature():
    records = build_dataset(
        "unused.pcap", _LABELS, "CIC-IDS-2017", feature_fn=_fixture_feature_fn
    )
    df = records_to_dataframe(records)

    assert len(df) == 2
    assert "label" in df.columns
    assert "dataset" in df.columns
    assert df.shape[1] == FEATURE_COUNT + 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dataset_builder.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.dataset_builder.builder'`

- [ ] **Step 3: Write `training/dataset_builder/builder.py`**

```python
"""Builds harmonized, FlowFeatures-compatible training records from a raw PCAP plus the
dataset's original per-flow label records, using the SAME flow-assembly/feature-computation code
the live device runs (FR-12.1) -- never a public dataset's own pre-computed flow/feature files,
since those have known flow-construction/labeling errors and a different feature pipeline for
training vs. inference would break generalization.

INTEGRATION POINT (flagged, parallel phase): this module imports compute_features_from_pcap from
services.flowextract.features, a module built by a different, concurrently-planned phase. The
exact function name/signature may need a one-line adjustment once that phase lands -- this import
is a deliberate, acknowledged integration point, not a placeholder in this module's own logic.
Expected signature:
    compute_features_from_pcap(pcap_path: str) -> list[dict]
where each dict has keys: src_ip, dst_ip, src_port, dst_port, protocol, start_time (epoch float),
end_time (epoch float), features (list[float] of length common.schemas.FEATURE_COUNT)."""
from __future__ import annotations

from typing import Callable, Optional

from common.schemas import FEATURE_COUNT, SCHEMA_VERSION, FlowFeatures
from training.dataset_builder.flow_label_matcher import match_flow_to_label
from training.dataset_builder.label_mapper import map_label
from training.feature_schema import get_feature_names

try:
    from services.flowextract.features import (
        compute_features_from_pcap as _compute_features_from_pcap,
    )
except ImportError:
    _compute_features_from_pcap = None


def build_dataset(
    pcap_path: str,
    label_records: list,
    dataset_name: str,
    time_tolerance_s: float = 1.0,
    feature_fn: Optional[Callable] = None,
) -> list:
    """Returns a list of harmonized records: {flow_id, src_ip, dst_ip, src_port, dst_port,
    protocol, start_time, end_time, features (FlowFeatures), label (one of
    label_mapper.TARGET_CLASSES, or None if no original label matched), dataset}.

    feature_fn overrides the services.flowextract import point -- used by tests to avoid
    depending on the parallel phase landing, and by callers that already have flows in memory."""
    compute_fn = feature_fn or _compute_features_from_pcap
    if compute_fn is None:
        raise RuntimeError(
            "services.flowextract.features.compute_features_from_pcap is not importable yet "
            "(parallel phase not landed) and no feature_fn override was supplied."
        )

    flows = compute_fn(pcap_path)
    records = []
    for i, flow in enumerate(flows):
        values = flow["features"]
        if len(values) != FEATURE_COUNT:
            raise ValueError(
                f"flow {i} produced {len(values)} features, expected {FEATURE_COUNT}"
            )

        native_label = match_flow_to_label(flow, label_records, time_tolerance_s)
        target_label = map_label(dataset_name, native_label) if native_label is not None else None

        records.append(
            {
                "flow_id": f"{dataset_name}:{i}",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "start_time": flow["start_time"],
                "end_time": flow["end_time"],
                "features": FlowFeatures(schema_version=SCHEMA_VERSION, values=list(values)),
                "label": target_label,
                "dataset": dataset_name,
            }
        )
    return records


def records_to_dataframe(records: list):
    """Flattens harmonized records (dropping flows with no matched original label) into a pandas
    DataFrame with one column per training.feature_schema.get_feature_names() entry plus 'label'
    and 'dataset', ready for Tasks 9-13's training/evaluation scripts."""
    import pandas as pd

    names = get_feature_names()
    rows = []
    for record in records:
        if record["label"] is None:
            continue
        row = dict(zip(names, record["features"].values))
        row["label"] = record["label"]
        row["dataset"] = record["dataset"]
        rows.append(row)
    return pd.DataFrame(rows)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dataset_builder.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add training/dataset_builder/builder.py tests/unit/test_dataset_builder.py
git commit -m "feat: add dataset builder (raw PCAP + original labels -> harmonized FlowFeatures records)"
```

---

## Task 9: Train the Layer 2 Isolation Forest (`training/train_iforest.py`)

**Files:**
- Create: `training/train_iforest.py`
- Test: `tests/unit/test_train_iforest.py`

**Interfaces:**
- Consumes: `training.feature_schema.{get_feature_names, get_extractor_version}` (Task 2),
  `training.packaging.save_model` (Task 3), `models.registry.ModelRegistry` (Task 4),
  `common.db.migrate.connect` (Phase 1).
- Produces: `train_iforest(benign_df, n_estimators=100, max_samples=256, random_state=42) ->
  IsolationForest`, `train_and_register(benign_df, version, out_dir, db_path, training_data_desc,
  n_estimators=100, max_samples=256) -> int` (returns the new, inactive `model_id`), plus a
  `main()` CLI entry point.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_train_iforest.py
import numpy as np
import pandas as pd

from common.db.migrate import connect
from training.feature_schema import get_feature_names
from training.train_iforest import train_and_register, train_iforest


def _tiny_benign_df(n=40):
    names = get_feature_names()
    rng = np.random.default_rng(0)
    data = rng.normal(loc=0.0, scale=1.0, size=(n, len(names)))
    return pd.DataFrame(data, columns=names)


def test_train_iforest_fits_and_scores_benign_data():
    df = _tiny_benign_df()
    model = train_iforest(df, n_estimators=10, max_samples=16)

    scores = model.decision_function(df[get_feature_names()].to_numpy())
    assert len(scores) == len(df)


def test_train_iforest_accepts_tunable_hyperparameters_not_hardcoded():
    df = _tiny_benign_df()
    model_a = train_iforest(df, n_estimators=5, max_samples=8)
    model_b = train_iforest(df, n_estimators=20, max_samples=20)

    assert model_a.n_estimators == 5
    assert model_b.n_estimators == 20


def test_train_and_register_creates_inactive_iforest_model_package_row(tmp_path):
    df = _tiny_benign_df()
    db_path = str(tmp_path / "test.sqlite3")

    model_id = train_and_register(
        df,
        version="0.1.0-test",
        out_dir=str(tmp_path / "artifacts"),
        db_path=db_path,
        training_data_desc={"n_samples": len(df)},
        n_estimators=10,
        max_samples=16,
    )

    conn = connect(db_path)
    row = conn.execute(
        "SELECT model_type, is_active, class_list FROM model_package WHERE model_id = ?",
        (model_id,),
    ).fetchone()
    assert row[0] == "IFOREST"
    assert row[1] == 0
    assert row[2] is None  # IFOREST is unsupervised -- no class list
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_train_iforest.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.train_iforest'`

- [ ] **Step 3: Write `training/train_iforest.py`**

```python
"""Trains the Layer 2 Isolation Forest anomaly model (Eq 5.2-5.3) on BENIGN-ONLY flows -- no
attack labels are used at fit time, since this is an unsupervised model. n_estimators/max_samples
default to the same values as the live device's anomaly.n_estimators/anomaly.subsample_size
config keys (100/256, see common/config_schema.py from Phase 1) but are accepted as tunable
arguments, never hardcoded, in case an operator retrains with different values later."""
from __future__ import annotations

import argparse

import pandas as pd
from sklearn.ensemble import IsolationForest

from common.db.migrate import connect
from models.registry import ModelRegistry
from training.feature_schema import get_extractor_version, get_feature_names
from training.packaging import save_model


def train_iforest(
    benign_df: pd.DataFrame,
    n_estimators: int = 100,
    max_samples: int = 256,
    random_state: int = 42,
) -> IsolationForest:
    """benign_df must contain only Benign-labeled rows, with one column per
    training.feature_schema.get_feature_names() entry -- no label column is used for fitting."""
    feature_cols = get_feature_names()
    X = benign_df[feature_cols].to_numpy()
    model = IsolationForest(
        n_estimators=n_estimators, max_samples=max_samples, random_state=random_state
    )
    model.fit(X)
    return model


def train_and_register(
    benign_df: pd.DataFrame,
    version: str,
    out_dir: str,
    db_path: str,
    training_data_desc: dict,
    n_estimators: int = 100,
    max_samples: int = 256,
) -> int:
    """Trains, packages, and registers an IFOREST model as an inactive model_package row.
    Promoting it to active is a separate, explicit step (see training/promote_model.py)."""
    model = train_iforest(benign_df, n_estimators=n_estimators, max_samples=max_samples)
    file_path = save_model(model, "IFOREST", version, out_dir)

    conn = connect(db_path)
    registry = ModelRegistry(conn)
    return registry.register(
        model_type="IFOREST",
        version=version,
        file_path=file_path,
        feature_list=get_feature_names(),
        extractor_version=get_extractor_version(),
        class_list=None,  # unsupervised -- no output classes
        training_data=training_data_desc,
        metrics=None,  # training/evaluate.py (Task 12) fills this in after test-set scoring
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Layer 2 Isolation Forest model.")
    parser.add_argument(
        "--benign-csv", required=True,
        help="CSV of benign-only flow features (from dataset_builder.records_to_dataframe output)",
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--out-dir", default="models/artifacts")
    parser.add_argument("--db-path", default="nidps.sqlite3")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-samples", type=int, default=256)
    args = parser.parse_args()

    benign_df = pd.read_csv(args.benign_csv)
    model_id = train_and_register(
        benign_df,
        version=args.version,
        out_dir=args.out_dir,
        db_path=args.db_path,
        training_data_desc={"source_csv": args.benign_csv, "n_samples": len(benign_df)},
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
    )
    print(f"Registered IFOREST model_id={model_id} (inactive -- promote with training.promote_model)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_train_iforest.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/train_iforest.py tests/unit/test_train_iforest.py
git commit -m "feat: add Layer 2 Isolation Forest training and registration script"
```

---

## Task 10: Train the Layer 3 Random Forest (`training/train_rf.py`)

**Files:**
- Create: `training/train_rf.py`
- Test: `tests/unit/test_train_rf.py`

**Interfaces:**
- Consumes: `training.feature_schema.{get_feature_names, get_extractor_version}` (Task 2),
  `training.packaging.save_model` (Task 3), `models.registry.ModelRegistry` (Task 4),
  `imbalanced_learn.under_sampling.RandomUnderSampler`.
- Produces: `train_rf(df, n_estimators=100, random_state=42, resample=True) ->
  RandomForestClassifier`, `train_test_register(df, version, out_dir, db_path,
  training_data_desc, test_size=0.2, n_estimators=100, resample=True, random_state=42) -> tuple[int,
  pandas.DataFrame, pandas.Series]` (returns `model_id` plus the held-out test split so
  `training/evaluate.py`, Task 12, can score it), plus a `main()` CLI entry point.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_train_rf.py
import json

import numpy as np
import pandas as pd

from common.db.migrate import connect
from training.feature_schema import get_feature_names
from training.train_rf import train_rf, train_test_register


def _tiny_multiclass_df(n_per_class=15):
    names = get_feature_names()
    rng = np.random.default_rng(1)
    rows, labels = [], []
    for label, offset in (("Benign", 0.0), ("DoS/DDoS", 6.0), ("Reconnaissance", -6.0)):
        rows.append(rng.normal(loc=offset, scale=0.3, size=(n_per_class, len(names))))
        labels.extend([label] * n_per_class)
    df = pd.DataFrame(np.vstack(rows), columns=names)
    df["label"] = labels
    return df


def test_train_rf_fits_and_predicts_known_classes():
    df = _tiny_multiclass_df()
    model = train_rf(df, n_estimators=10)

    preds = model.predict(df[get_feature_names()].to_numpy())
    assert set(preds) <= {"Benign", "DoS/DDoS", "Reconnaissance"}
    assert model.criterion == "gini"
    assert model.max_features == "sqrt"


def test_train_test_register_returns_held_out_split_disjoint_from_training(tmp_path):
    df = _tiny_multiclass_df()
    db_path = str(tmp_path / "test.sqlite3")

    model_id, X_test, y_test = train_test_register(
        df, version="0.1.0-test", out_dir=str(tmp_path / "artifacts"), db_path=db_path,
        training_data_desc={"n_samples": len(df)}, n_estimators=10,
    )

    assert len(X_test) == len(y_test)
    assert 0 < len(X_test) < len(df)


def test_train_test_register_creates_model_package_row_with_class_list(tmp_path):
    df = _tiny_multiclass_df()
    db_path = str(tmp_path / "test.sqlite3")

    model_id, _, _ = train_test_register(
        df, version="0.1.0-test", out_dir=str(tmp_path / "artifacts"), db_path=db_path,
        training_data_desc={"n_samples": len(df)}, n_estimators=10,
    )

    conn = connect(db_path)
    row = conn.execute(
        "SELECT model_type, class_list FROM model_package WHERE model_id = ?", (model_id,)
    ).fetchone()
    assert row[0] == "RF"
    classes = set(json.loads(row[1]))
    assert classes <= {"Benign", "DoS/DDoS", "Reconnaissance"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_train_rf.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.train_rf'`

- [ ] **Step 3: Write `training/train_rf.py`**

```python
"""Trains the Layer 3 Random Forest classifier (Eq 5.6) on the 7-class harmonized flow data.
Class imbalance (Benign vastly outnumbers most attack classes) is handled with imbalanced-learn's
RandomUnderSampler rather than SMOTE: several of our 78 features are small-integer counts/ratios
(packet counts, flag counts) where SMOTE's linear interpolation between neighbors can produce
physically implausible synthetic flows (e.g. fractional packet counts); undersampling the majority
class(es) preserves only real observed flows."""
from __future__ import annotations

import argparse

import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from common.db.migrate import connect
from models.registry import ModelRegistry
from training.feature_schema import get_extractor_version, get_feature_names
from training.packaging import save_model


def train_rf(
    df: pd.DataFrame,
    n_estimators: int = 100,
    random_state: int = 42,
    resample: bool = True,
) -> RandomForestClassifier:
    """df must have one column per training.feature_schema.get_feature_names() entry plus a
    'label' column whose values are a subset of label_mapper.TARGET_CLASSES."""
    feature_cols = get_feature_names()
    X = df[feature_cols].to_numpy()
    y = df["label"].to_numpy()

    if resample:
        X, y = RandomUnderSampler(random_state=random_state).fit_resample(X, y)

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        criterion="gini",
        max_features="sqrt",
        random_state=random_state,
    )
    model.fit(X, y)
    return model


def train_test_register(
    df: pd.DataFrame,
    version: str,
    out_dir: str,
    db_path: str,
    training_data_desc: dict,
    test_size: float = 0.2,
    n_estimators: int = 100,
    resample: bool = True,
    random_state: int = 42,
):
    """Splits df into train/test (stratified by label), fits on train, registers an inactive RF
    model_package row, and returns (model_id, X_test, y_test) -- the held-out set the model never
    saw -- so training/evaluate.py (Task 12) can score it and write back real test metrics."""
    feature_cols = get_feature_names()
    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=df["label"]
    )

    model = train_rf(train_df, n_estimators=n_estimators, resample=resample, random_state=random_state)
    file_path = save_model(model, "RF", version, out_dir)

    conn = connect(db_path)
    registry = ModelRegistry(conn)
    model_id = registry.register(
        model_type="RF",
        version=version,
        file_path=file_path,
        feature_list=feature_cols,
        extractor_version=get_extractor_version(),
        class_list=sorted(df["label"].unique().tolist()),
        training_data=training_data_desc,
        metrics=None,
    )
    return model_id, test_df[feature_cols], test_df["label"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Layer 3 Random Forest classifier.")
    parser.add_argument("--dataset-csv", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out-dir", default="models/artifacts")
    parser.add_argument("--db-path", default="nidps.sqlite3")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--no-resample", action="store_true")
    args = parser.parse_args()

    df = pd.read_csv(args.dataset_csv)
    model_id, _, _ = train_test_register(
        df,
        version=args.version,
        out_dir=args.out_dir,
        db_path=args.db_path,
        training_data_desc={"source_csv": args.dataset_csv, "n_samples": len(df)},
        n_estimators=args.n_estimators,
        resample=not args.no_resample,
    )
    print(f"Registered RF model_id={model_id} (inactive -- promote with training.promote_model)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_train_rf.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/train_rf.py tests/unit/test_train_rf.py
git commit -m "feat: add Layer 3 Random Forest training and registration script"
```

---

## Task 11: Train the Layer 3 XGBoost classifier (`training/train_xgb.py`)

**Files:**
- Create: `training/train_xgb.py`
- Test: `tests/unit/test_train_xgb.py`

**Interfaces:**
- Consumes: `training.feature_schema.{get_feature_names, get_extractor_version}` (Task 2),
  `training.packaging.save_model` (Task 3, saves native JSON for this model type),
  `models.registry.ModelRegistry` (Task 4), `imbalanced_learn.under_sampling.RandomUnderSampler`.
- Produces: `train_xgb(df, class_list, n_estimators=100, gamma=0.0, reg_lambda=1.0,
  random_state=42, resample=True) -> xgboost.XGBClassifier`, `train_test_register(df, version,
  out_dir, db_path, training_data_desc, test_size=0.2, n_estimators=100, gamma=0.0,
  reg_lambda=1.0, resample=True, random_state=42) -> tuple[int, pandas.DataFrame, pandas.Series,
  list[str]]`, plus a `main()` CLI entry point.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_train_xgb.py
import json

import numpy as np
import pandas as pd

from common.db.migrate import connect
from training.feature_schema import get_feature_names
from training.train_xgb import train_test_register, train_xgb


def _tiny_multiclass_df(n_per_class=15):
    names = get_feature_names()
    rng = np.random.default_rng(2)
    rows, labels = [], []
    for label, offset in (("Benign", 0.0), ("DoS/DDoS", 6.0), ("Reconnaissance", -6.0)):
        rows.append(rng.normal(loc=offset, scale=0.3, size=(n_per_class, len(names))))
        labels.extend([label] * n_per_class)
    df = pd.DataFrame(np.vstack(rows), columns=names)
    df["label"] = labels
    return df


def test_train_xgb_fits_with_tunable_gamma_and_reg_lambda():
    df = _tiny_multiclass_df()
    class_list = sorted(df["label"].unique().tolist())

    model = train_xgb(df, class_list, n_estimators=10, gamma=0.5, reg_lambda=2.0)

    assert model.get_params()["gamma"] == 0.5
    assert model.get_params()["reg_lambda"] == 2.0

    preds = model.predict(df[get_feature_names()].to_numpy())
    assert set(preds.tolist()) <= set(range(len(class_list)))


def test_train_test_register_saves_native_json_and_registers_xgb_row(tmp_path):
    df = _tiny_multiclass_df()
    db_path = str(tmp_path / "test.sqlite3")

    model_id, X_test, y_test, class_list = train_test_register(
        df, version="0.1.0-test", out_dir=str(tmp_path / "artifacts"), db_path=db_path,
        training_data_desc={"n_samples": len(df)}, n_estimators=10,
    )

    assert len(X_test) == len(y_test)
    assert set(class_list) <= {"Benign", "DoS/DDoS", "Reconnaissance"}

    conn = connect(db_path)
    row = conn.execute(
        "SELECT model_type, file_path, class_list FROM model_package WHERE model_id = ?",
        (model_id,),
    ).fetchone()
    assert row[0] == "XGB"
    assert row[1].endswith(".json")
    assert set(json.loads(row[2])) == set(class_list)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_train_xgb.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.train_xgb'`

- [ ] **Step 3: Write `training/train_xgb.py`**

```python
"""Trains the Layer 3 XGBoost classifier (Eq 5.7) on the 7-class harmonized flow data, with
gamma/reg_lambda as tunable hyperparameters. XGBoost's sklearn wrapper is most reliably
numeric-label-only across versions, so labels are explicitly encoded to integers here using a
fixed, sorted class_list (index == encoded label) rather than relying on XGBClassifier's own
internal encoder -- the same sorted class_list is stored in model_package.class_list so a caller
can map predictions back to class names deterministically. Class imbalance is handled the same
way as training/train_rf.py (RandomUnderSampler, not SMOTE -- see that module's docstring)."""
from __future__ import annotations

import argparse

import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from common.db.migrate import connect
from models.registry import ModelRegistry
from training.feature_schema import get_extractor_version, get_feature_names
from training.packaging import save_model


def train_xgb(
    df: pd.DataFrame,
    class_list: list,
    n_estimators: int = 100,
    gamma: float = 0.0,
    reg_lambda: float = 1.0,
    random_state: int = 42,
    resample: bool = True,
) -> XGBClassifier:
    """df must have one column per training.feature_schema.get_feature_names() entry plus a
    'label' column. class_list fixes the integer encoding order (index == encoded label)."""
    feature_cols = get_feature_names()
    class_index = {name: i for i, name in enumerate(class_list)}

    X = df[feature_cols].to_numpy()
    y = df["label"].map(class_index).to_numpy()

    if resample:
        X, y = RandomUnderSampler(random_state=random_state).fit_resample(X, y)

    model = XGBClassifier(
        n_estimators=n_estimators,
        gamma=gamma,
        reg_lambda=reg_lambda,
        random_state=random_state,
        eval_metric="mlogloss",
    )
    model.fit(X, y)
    return model


def train_test_register(
    df: pd.DataFrame,
    version: str,
    out_dir: str,
    db_path: str,
    training_data_desc: dict,
    test_size: float = 0.2,
    n_estimators: int = 100,
    gamma: float = 0.0,
    reg_lambda: float = 1.0,
    resample: bool = True,
    random_state: int = 42,
):
    """Splits df into train/test (stratified by label), fits on train, saves the model as native
    XGBoost JSON (never pickle -- see training/packaging.py), registers an inactive XGB
    model_package row, and returns (model_id, X_test, y_test, class_list) so
    training/evaluate.py (Task 12) can score the held-out set."""
    feature_cols = get_feature_names()
    class_list = sorted(df["label"].unique().tolist())

    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=df["label"]
    )

    model = train_xgb(
        train_df,
        class_list,
        n_estimators=n_estimators,
        gamma=gamma,
        reg_lambda=reg_lambda,
        resample=resample,
        random_state=random_state,
    )
    file_path = save_model(model, "XGB", version, out_dir)

    conn = connect(db_path)
    registry = ModelRegistry(conn)
    model_id = registry.register(
        model_type="XGB",
        version=version,
        file_path=file_path,
        feature_list=feature_cols,
        extractor_version=get_extractor_version(),
        class_list=class_list,
        training_data=training_data_desc,
        metrics=None,
    )
    return model_id, test_df[feature_cols], test_df["label"], class_list


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Layer 3 XGBoost classifier.")
    parser.add_argument("--dataset-csv", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out-dir", default="models/artifacts")
    parser.add_argument("--db-path", default="nidps.sqlite3")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--gamma", type=float, default=0.0)
    parser.add_argument("--reg-lambda", type=float, default=1.0)
    parser.add_argument("--no-resample", action="store_true")
    args = parser.parse_args()

    df = pd.read_csv(args.dataset_csv)
    model_id, _, _, _ = train_test_register(
        df,
        version=args.version,
        out_dir=args.out_dir,
        db_path=args.db_path,
        training_data_desc={"source_csv": args.dataset_csv, "n_samples": len(df)},
        n_estimators=args.n_estimators,
        gamma=args.gamma,
        reg_lambda=args.reg_lambda,
        resample=not args.no_resample,
    )
    print(f"Registered XGB model_id={model_id} (inactive -- promote with training.promote_model)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_train_xgb.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add training/train_xgb.py tests/unit/test_train_xgb.py
git commit -m "feat: add Layer 3 XGBoost training and registration script (native JSON, never pickle)"
```

---

## Task 12: Evaluation script — metrics, AUPRC, Suricata comparison (`training/evaluate.py`)

**Files:**
- Create: `training/evaluate.py`
- Test: `tests/unit/test_evaluate.py`

**Interfaces:**
- Consumes: `training.packaging.load_model` (Task 3), `models.registry.ModelRegistry` (Task 4),
  `training.feature_schema.get_feature_names` (Task 2), `common.db.migrate.connect` (Phase 1).
- Produces: `classification_metrics(y_true, y_pred, labels) -> dict` (precision/recall/F1 macro
  + per-class including per-class false-positive rate), `iforest_auprc(y_true_is_benign,
  anomaly_scores) -> float`, `write_suricata_comparison_csv(out_path, trained_model_name,
  trained_model_f1_macro, suricata_f1_macro) -> None` (NFR-11), `write_metrics_json(out_path,
  metrics) -> None`, plus a `main()` CLI entry point that scores a saved model against a held-out
  test CSV and calls `ModelRegistry.update_metrics()`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_evaluate.py
import csv

from training.evaluate import (
    classification_metrics,
    iforest_auprc,
    write_suricata_comparison_csv,
)


def test_classification_metrics_perfect_predictions():
    y_true = ["Benign", "Benign", "DoS/DDoS", "DoS/DDoS"]
    y_pred = ["Benign", "Benign", "DoS/DDoS", "DoS/DDoS"]

    metrics = classification_metrics(y_true, y_pred, labels=["Benign", "DoS/DDoS"])

    assert metrics["precision_macro"] == 1.0
    assert metrics["recall_macro"] == 1.0
    assert metrics["f1_macro"] == 1.0
    assert metrics["per_class"]["Benign"]["false_positive_rate"] == 0.0
    assert metrics["per_class"]["DoS/DDoS"]["false_positive_rate"] == 0.0


def test_classification_metrics_detects_false_positives():
    y_true = ["Benign", "Benign", "DoS/DDoS"]
    y_pred = ["DoS/DDoS", "Benign", "DoS/DDoS"]  # 1 of 2 Benign flows misclassified as DoS/DDoS

    metrics = classification_metrics(y_true, y_pred, labels=["Benign", "DoS/DDoS"])

    assert metrics["per_class"]["DoS/DDoS"]["false_positive_rate"] == 0.5
    assert metrics["f1_macro"] < 1.0


def test_iforest_auprc_perfect_separation_scores_near_one():
    is_benign = [True, True, True, False, False]
    anomaly_scores = [0.0, 0.1, 0.05, 0.9, 0.95]  # attacks score higher (more anomalous)

    auprc = iforest_auprc(is_benign, anomaly_scores)

    assert auprc > 0.9


def test_iforest_auprc_random_separation_scores_lower():
    is_benign = [True, False, True, False, True, False]
    anomaly_scores = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]  # no separation at all

    auprc = iforest_auprc(is_benign, anomaly_scores)

    assert 0.0 <= auprc <= 1.0


def test_write_suricata_comparison_csv_writes_expected_rows(tmp_path):
    out_path = str(tmp_path / "comparison.csv")

    write_suricata_comparison_csv(out_path, "XGBoost-v1", 0.91, 0.68)

    with open(out_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["system", "f1_macro"]
    assert rows[1] == ["XGBoost-v1", "0.9100"]
    assert rows[2] == ["Suricata-alone", "0.6800"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_evaluate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.evaluate'`

- [ ] **Step 3: Write `training/evaluate.py`**

```python
"""Computes detection metrics (spec Section 5.10.1): Precision, Recall, F1 (macro-averaged
overall and per-class), False Positive Rate per class, and Area-Under-Precision-Recall-Curve
specifically for the Isolation Forest (Layer 2) model. Also runs the NFR-11 comparison: trained
model macro-F1 vs Suricata-alone macro-F1 on the same labeled test set, writing a comparison CSV.
This script computes that comparison from real predictions supplied by the caller -- it does not
fabricate or hardcode a result; running it against real self-collected test data and reporting
whatever number comes out is the actual NFR-11 experiment."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def classification_metrics(y_true: list, y_pred: list, labels: list) -> dict:
    """Precision/Recall/F1 macro-averaged overall, plus per-class precision/recall/F1 and
    per-class False Positive Rate computed from a one-vs-rest confusion matrix."""
    precision_macro = precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    recall_macro = recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    f1_macro = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)

    confusion = confusion_matrix(y_true, y_pred, labels=labels)
    per_class = {}
    for i, label in enumerate(labels):
        tp = int(confusion[i, i])
        fn = int(confusion[i, :].sum()) - tp
        fp = int(confusion[:, i].sum()) - tp
        tn = int(confusion.sum()) - tp - fn - fp
        per_class[label] = {
            "precision": float(
                precision_score(y_true, y_pred, labels=[label], average="micro", zero_division=0)
            ),
            "recall": float(
                recall_score(y_true, y_pred, labels=[label], average="micro", zero_division=0)
            ),
            "f1": float(
                f1_score(y_true, y_pred, labels=[label], average="micro", zero_division=0)
            ),
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        }

    return {
        "precision_macro": float(precision_macro),
        "recall_macro": float(recall_macro),
        "f1_macro": float(f1_macro),
        "per_class": per_class,
    }


def iforest_auprc(y_true_is_benign: list, anomaly_scores: list) -> float:
    """Area-Under-Precision-Recall-Curve for the Isolation Forest, treating 'anomalous' (not
    benign) as the positive class. anomaly_scores must be higher = more anomalous (pass
    -model.decision_function(X), since sklearn's IsolationForest.decision_function is
    higher = more normal)."""
    y_positive = [0 if is_benign else 1 for is_benign in y_true_is_benign]
    return float(average_precision_score(y_positive, anomaly_scores))


def write_suricata_comparison_csv(
    out_path: str,
    trained_model_name: str,
    trained_model_f1_macro: float,
    suricata_f1_macro: float,
) -> None:
    """NFR-11: writes a 2-row comparison table (system, macro-F1) to out_path. Call this with
    real numbers from classification_metrics() computed on the same labeled test set for both the
    trained model's predictions and Suricata's own alert-derived class predictions -- never with
    placeholder numbers."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["system", "f1_macro"])
        writer.writerow([trained_model_name, f"{trained_model_f1_macro:.4f}"])
        writer.writerow(["Suricata-alone", f"{suricata_f1_macro:.4f}"])


def write_metrics_json(out_path: str, metrics: dict) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def main() -> None:
    import argparse

    import pandas as pd

    from common.db.migrate import connect
    from models.registry import ModelRegistry
    from training.feature_schema import get_feature_names
    from training.packaging import load_model

    parser = argparse.ArgumentParser(description="Score a trained model on a held-out test set.")
    parser.add_argument("--model-type", required=True, choices=["IFOREST", "RF", "XGB"])
    parser.add_argument("--model-id", type=int, required=True)
    parser.add_argument("--file-path", required=True)
    parser.add_argument("--test-csv", required=True, help="Must have feature columns + 'label'")
    parser.add_argument("--db-path", default="nidps.sqlite3")
    parser.add_argument("--out-json", default="training/reports/metrics.json")
    args = parser.parse_args()

    feature_cols = get_feature_names()
    df = pd.read_csv(args.test_csv)
    X = df[feature_cols].to_numpy()
    y_true = df["label"].tolist()

    model = load_model(args.model_type, args.file_path)
    conn = connect(args.db_path)

    if args.model_type == "IFOREST":
        anomaly_scores = (-model.decision_function(X)).tolist()
        is_benign = [label == "Benign" for label in y_true]
        metrics = {"auprc": iforest_auprc(is_benign, anomaly_scores)}
    else:
        row = conn.execute(
            "SELECT class_list FROM model_package WHERE model_id = ?", (args.model_id,)
        ).fetchone()
        class_list = json.loads(row[0]) if row and row[0] else sorted(set(y_true))

        y_pred_raw = model.predict(X)
        if args.model_type == "XGB":
            index_to_class = {i: name for i, name in enumerate(class_list)}
            y_pred = [index_to_class[int(i)] for i in y_pred_raw]
        else:
            y_pred = [str(p) for p in y_pred_raw]

        labels = sorted(set(y_true) | set(y_pred))
        metrics = classification_metrics(y_true, y_pred, labels)

    write_metrics_json(args.out_json, metrics)
    ModelRegistry(conn).update_metrics(args.model_id, metrics)
    print(f"Wrote metrics to {args.out_json} and updated model_package.metrics for model_id={args.model_id}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_evaluate.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add training/evaluate.py tests/unit/test_evaluate.py
git commit -m "feat: add evaluation script (classification metrics, IFOREST AUPRC, NFR-11 comparison)"
```

---

## Task 13: Cross-dataset generalization matrix (`training/cross_dataset_matrix.py`)

**Files:**
- Create: `training/cross_dataset_matrix.py`
- Test: `tests/unit/test_cross_dataset_matrix.py`

**Interfaces:**
- Consumes: `training.feature_schema.get_feature_names` (Task 2).
- Produces: `PUBLIC_DATASETS: list[str]`, `ALL_PUBLIC_COMBINED: str`,
  `run_cross_dataset_matrix(datasets: dict[str, pandas.DataFrame], model_factory: Callable[[],
  object], out_csv: str, test_size: float = 0.3, random_state: int = 42) -> pandas.DataFrame`.
  This is the script that fills in the spec's Table 5.6 template from real experiments.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_cross_dataset_matrix.py
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from training.cross_dataset_matrix import ALL_PUBLIC_COMBINED, run_cross_dataset_matrix
from training.feature_schema import get_feature_names


def _tiny_df(seed, n_per_class=12):
    names = get_feature_names()
    rng = np.random.default_rng(seed)
    rows, labels = [], []
    for label, offset in (("Benign", 0.0), ("DoS/DDoS", 6.0)):
        rows.append(rng.normal(loc=offset, scale=0.3, size=(n_per_class, len(names))))
        labels.extend([label] * n_per_class)
    df = pd.DataFrame(np.vstack(rows), columns=names)
    df["label"] = labels
    return df


def test_cross_dataset_matrix_covers_every_train_test_pair_and_writes_csv(tmp_path):
    datasets = {
        "CIC-IDS-2017": _tiny_df(1),
        "CSE-CIC-IDS2018": _tiny_df(2),
        "CIC-IoT-2023": _tiny_df(3),
        "Self-collected": _tiny_df(4),
    }
    out_csv = str(tmp_path / "matrix.csv")

    matrix = run_cross_dataset_matrix(
        datasets,
        model_factory=lambda: RandomForestClassifier(
            n_estimators=10, criterion="gini", max_features="sqrt"
        ),
        out_csv=out_csv,
        test_size=0.3,
    )

    assert set(matrix.columns) == set(datasets.keys())
    assert set(datasets.keys()) <= set(matrix.index)
    assert ALL_PUBLIC_COMBINED in matrix.index
    assert not matrix.isnull().values.any()
    assert os.path.exists(out_csv)


def test_cross_dataset_matrix_diagonal_entries_score_higher_than_chance(tmp_path):
    datasets = {
        "CIC-IDS-2017": _tiny_df(10),
        "CSE-CIC-IDS2018": _tiny_df(20),
    }
    out_csv = str(tmp_path / "matrix.csv")

    matrix = run_cross_dataset_matrix(
        datasets,
        model_factory=lambda: RandomForestClassifier(
            n_estimators=10, criterion="gini", max_features="sqrt"
        ),
        out_csv=out_csv,
        test_size=0.3,
    )

    # In-distribution (diagonal) scores on this well-separated synthetic data should be high.
    assert matrix.loc["CIC-IDS-2017", "CIC-IDS-2017"] > 0.5
    assert matrix.loc["CSE-CIC-IDS2018", "CSE-CIC-IDS2018"] > 0.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/unit/test_cross_dataset_matrix.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.cross_dataset_matrix'`

- [ ] **Step 3: Write `training/cross_dataset_matrix.py`**

```python
"""Builds the spec's Table 5.6 cross-dataset generalization matrix: trains a fresh model (from
model_factory) on each of {CIC-IDS-2017, CSE-CIC-IDS2018, CIC-IoT-2023, Self-collected} plus an
'All-Public-Combined' row (the three public datasets' train splits concatenated, per the source
report's "all three public combined" training configuration), then tests every trained model
against every dataset's held-out test split (diagonal = in-distribution, off-diagonal =
cross-dataset generalization), writing the resulting macro-F1 matrix to out_csv. This produces
whatever numbers come out of running it against real harmonized dataset DataFrames (from
training.dataset_builder.builder.records_to_dataframe) -- it is the experiment itself, not a
place to put expected/fabricated numbers.

Note: this script is written against classifiers whose fit()/predict() accept the original
string class labels directly (e.g. sklearn's RandomForestClassifier, used for Table 5.6 in the
source report). Running it with an XGBoost model_factory would require pre-encoding labels to
integers first, the way training/train_xgb.py does -- that encoding/decoding step is the
caller's responsibility if they choose to run this matrix with XGBoost instead of Random Forest."""
from __future__ import annotations

from typing import Callable

import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

from training.feature_schema import get_feature_names

PUBLIC_DATASETS = ["CIC-IDS-2017", "CSE-CIC-IDS2018", "CIC-IoT-2023"]
ALL_PUBLIC_COMBINED = "All-Public-Combined"


def _split(df: pd.DataFrame, test_size: float, random_state: int):
    return train_test_split(df, test_size=test_size, random_state=random_state, stratify=df["label"])


def run_cross_dataset_matrix(
    datasets: dict,
    model_factory: Callable[[], object],
    out_csv: str,
    test_size: float = 0.3,
    random_state: int = 42,
) -> pd.DataFrame:
    feature_cols = get_feature_names()
    splits = {name: _split(df, test_size, random_state) for name, df in datasets.items()}

    train_configs = {name: splits[name][0] for name in datasets}
    available_public = [name for name in PUBLIC_DATASETS if name in splits]
    if available_public:
        train_configs[ALL_PUBLIC_COMBINED] = pd.concat(
            [splits[name][0] for name in available_public], ignore_index=True
        )

    test_targets = list(datasets.keys())
    matrix = pd.DataFrame(index=list(train_configs.keys()), columns=test_targets, dtype=float)

    for train_name, train_df in train_configs.items():
        model = model_factory()
        model.fit(train_df[feature_cols].to_numpy(), train_df["label"].to_numpy())

        for test_name in test_targets:
            _, test_df = splits[test_name]
            X_test = test_df[feature_cols].to_numpy()
            y_test = test_df["label"].to_numpy()
            y_pred = model.predict(X_test)
            labels = sorted(set(y_test) | set(y_pred))
            matrix.loc[train_name, test_name] = f1_score(
                y_test, y_pred, labels=labels, average="macro", zero_division=0
            )

    matrix.to_csv(out_csv)
    return matrix
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/unit/test_cross_dataset_matrix.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add training/cross_dataset_matrix.py tests/unit/test_cross_dataset_matrix.py
git commit -m "feat: add cross-dataset generalization matrix script (spec Table 5.6)"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:**
  - FR-12.1 (same flow extractor for training and inference) → Task 8's flagged
    `services.flowextract.features.compute_features_from_pcap` import point, with Task 2's
    `get_feature_names()`/`get_extractor_version()` providing the matching feature list/version.
  - FR-12.2 (train/test offline) → the whole plan runs on a training workstation; nothing in
    `training/`/`models/` runs on the live device.
  - FR-12.3 (model package contents) → Task 4's `ModelRegistry.register()` persists model file,
    feature list (via `feature_list_hash`), extractor version, class list, training date (the
    table's own `deployed_at` default), and test results (`update_metrics()`, Task 12).
  - FR-12.4 (refuse incompatible schema) → Task 5's `verify_compatible()`.
  - FR-12.5 (additive rollback) → Task 4's `activate()`/`rollback()`, never deleting rows.
  - NFR-11 (beat Suricata-alone on self-collected test data) → Task 12's
    `write_suricata_comparison_csv()`, run as a real experiment, not hardcoded.
  - NFR-17 (no traffic interruption on model swap) → documented as a structural consequence of
    FR-12.5's flag-flip design; the live device's periodic `is_active` re-check is the other
    phases' responsibility, noted in Global Constraints.
  - NFR-19 (reusable training pipeline) → satisfied by import-based dependency on
    `services.flowextract.features`, never a running service call.
  - Isolation Forest (Eq 5.2-5.3), Random Forest (Eq 5.6), XGBoost (Eq 5.7) → Tasks 9, 10, 11
    respectively, each using the exact library/hyperparameter names specified, all tunable.
  - Class imbalance handling → Task 10/11's `RandomUnderSampler`, documented rationale.
  - XGBoost-never-pickle security requirement → Task 3's `save_model()`/`load_model()` plus three
    explicit tests (source-scan, pickle-monkeypatch, JSON-validity).
  - Dataset label harmonization for CIC-IDS-2017, CSE-CIC-IDS2018, CIC-IoT-2023, self-collected →
    Task 6's four mapping tables onto the 7 `TARGET_CLASSES`.
  - Cross-dataset generalization matrix (Table 5.6) → Task 13.
  - Detection metrics (Section 5.10.1: Precision/Recall/F1 macro + per-class, FPR, AUPRC for
    IFOREST) → Task 12's `classification_metrics()`/`iforest_auprc()`.
  - `ModelRegistry` class-diagram methods → Task 4 implements the brief's explicit
    `register/activate/load/rollback` signature set (which supersedes the source UML's vaguer
    `load(version)`/`activeVersion()` naming, since the brief's concrete signatures take
    precedence over the looser diagram description) plus `update_metrics()` for FR-12.3's test
    results.
  - `CalibrationState` — explicitly not written by this plan (Global Constraints note);
    confirmed no task inserts into `calibration_state`.
- **Placeholder scan:** every step has complete, runnable code and literal expected test output;
  no `TODO`/`TBD`/"similar to Task N" patterns; the two deliberately-flagged parallel-phase
  integration points (Task 2's feature list/version fallback, Task 8's `compute_features_from_pcap`
  fallback) are documented as acknowledged integration seams with a working fallback path, not
  unresolved placeholders — both are covered by passing tests that exercise the fallback branch.
- **Type consistency:** `model_type` string literals (`"IFOREST"`, `"RF"`, `"XGB"`) match the
  database's own `CHECK (model_type IN ('IFOREST', 'RF', 'XGB'))` constraint (Phase 1) exactly in
  every task that touches `model_package`. `ModelRegistry.register()`'s parameter names
  (`feature_list`, `extractor_version`, `class_list`, `training_data`, `metrics`) are used
  identically by Tasks 9, 10, and 11's `train_and_register`/`train_test_register` functions. The 7
  `TARGET_CLASSES` strings defined in Task 6 are the exact strings written to `class_list` by
  Tasks 10 and 11 and read back by Task 12 — no second, drifted copy of the class-name list exists
  anywhere in this plan.
