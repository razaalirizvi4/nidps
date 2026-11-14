"""Layer 2 training: fit the Isolation Forest on benign flows only (Section 5.5.1) and register it.

    python -m training.train_iforest --features data/features/cicids2017-monday \\
        --db data/nidps.sqlite3 --activate

What it writes:
  * models/artifacts/iforest-<version>.joblib   the fitted model
  * a model_package row (feature hash + extractor version, so the device can refuse a mismatch)
  * a calibration_state row holding the starting global threshold tau_g and u_max

tau_g is the p-th percentile (anomaly.calibration_percentile, default 99.5) of the model's scores
on benign flows it was NOT trained on, so it is a measured false-positive rate and not a guess.
The device then moves tau within +/- anomaly.calibration_max_shift of tau_g using local traffic
(Algorithm 5.4); it never retrains this model."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from common import config_loader
from common.schemas import utc_now_iso
from models.registry import ModelRegistry
from services.flowextract.features import FEATURE_NAMES
from training.feature_schema import current_extractor_version, feature_list_hash

_FWD_BYTES_IDX = FEATURE_NAMES.index("total_fwd_bytes")


def load_feature_sets(dirs: Sequence, max_per_set: Optional[int] = None, seed: int = 42) -> tuple:
    """Stacks features.npz from each directory. max_per_set caps every set to the same size at
    most, so one large dataset cannot drown out the others."""
    rng = np.random.default_rng(seed)
    parts, used = [], []
    for d in dirs:
        with np.load(Path(d) / "features.npz", allow_pickle=False) as data:
            names = [str(n) for n in data["feature_names"]]
            if names != list(FEATURE_NAMES):
                raise ValueError(f"{d}: feature columns do not match the current extractor")
            X = data["X"]
        if max_per_set is not None and len(X) > max_per_set:
            X = X[rng.choice(len(X), size=max_per_set, replace=False)]
        parts.append(X)
        used.append({"path": str(d), "flows": int(len(X))})
    return np.vstack(parts), used


def train_iforest(
    X, n_estimators: int = 100, max_samples: int = 256, random_state: int = 42
) -> IsolationForest:
    return IsolationForest(
        n_estimators=n_estimators, max_samples=max_samples, random_state=random_state
    ).fit(X)


def score_matrix(model: IsolationForest, X) -> np.ndarray:
    """Eq 5.2-5.3 anomaly scores in [0, 1], the same convention as AnomalyDetector.score()
    (sklearn's score_samples is the negative of the paper's score)."""
    return np.clip(-model.score_samples(X), 0.0, 1.0)


def run_training(
    conn,
    X,
    out_dir,
    version: Optional[str] = None,
    holdout_fraction: float = 0.2,
    n_estimators: Optional[int] = None,
    max_samples: Optional[int] = None,
    percentile: Optional[float] = None,
    seed: int = 42,
    sources: Optional[list] = None,
    activate: bool = False,
) -> int:
    import joblib

    if len(X) < 100:
        raise ValueError(f"only {len(X)} benign flows; need at least 100 to train and hold out")
    n_estimators = n_estimators or config_loader.get(conn, "anomaly.n_estimators")
    max_samples = max_samples or config_loader.get(conn, "anomaly.subsample_size")
    percentile = percentile or config_loader.get(conn, "anomaly.calibration_percentile")
    u_max_percentile = config_loader.get(conn, "exfil.u_max_percentile")
    version = version or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    rng = np.random.default_rng(seed)
    order = rng.permutation(len(X))
    n_holdout = max(int(len(X) * holdout_fraction), 50)
    holdout, train = X[order[:n_holdout]], X[order[n_holdout:]]

    model = train_iforest(train, n_estimators, max_samples, seed)
    holdout_scores = score_matrix(model, holdout)
    tau_global = float(np.percentile(holdout_scores, percentile))
    u_max = int(np.percentile(X[:, _FWD_BYTES_IDX], u_max_percentile))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = (out_dir / f"iforest-{version}.joblib").resolve()
    joblib.dump(model, model_path)

    metrics = {
        "train_flows": int(len(train)),
        "holdout_flows": int(len(holdout)),
        "n_estimators": n_estimators,
        "max_samples": max_samples,
        "tau_global": tau_global,
        "calibration_percentile": percentile,
        "holdout_score_mean": float(holdout_scores.mean()),
        "holdout_score_p50": float(np.percentile(holdout_scores, 50)),
        "holdout_score_p99": float(np.percentile(holdout_scores, 99)),
        "holdout_score_max": float(holdout_scores.max()),
        "u_max_bytes": u_max,
    }
    registry = ModelRegistry(conn)
    model_id = registry.register(
        "IFOREST", version, str(model_path), feature_list_hash(), current_extractor_version(),
        training_data={"sources": sources or [], "benign_only": True, "seed": seed},
        metrics=metrics,
    )
    now = utc_now_iso()
    conn.execute(
        """INSERT INTO calibration_state
               (model_id, tau, tau_global, percentile, sample_count, u_max, window_start,
                window_end, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (model_id, tau_global, tau_global, percentile, int(len(holdout)), u_max, now, now, now),
    )
    conn.commit()
    if activate:
        registry.activate(model_id)
    return model_id


def main(argv=None) -> int:
    from common.db.migrate import connect

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--features", nargs="+", required=True,
                        help="directories written by training.build_features (benign flows only)")
    parser.add_argument("--db", required=True, help="SQLite database to register the model in")
    parser.add_argument("--out-dir", default="models/artifacts")
    parser.add_argument("--version", default=None)
    parser.add_argument("--max-per-set", type=int, default=None,
                        help="cap flows taken from each feature set")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--activate", action="store_true", help="make this the active model")
    args = parser.parse_args(argv)

    X, sources = load_feature_sets(args.features, args.max_per_set, args.seed)
    print(f"training on {len(X):,} benign flows from {len(sources)} set(s)")
    conn = connect(args.db)
    config_loader.seed_defaults(conn)
    model_id = run_training(
        conn, X, args.out_dir, version=args.version, seed=args.seed, sources=sources,
        activate=args.activate,
    )
    row = conn.execute("SELECT version, file_path, metrics, is_active FROM model_package WHERE model_id = ?",
                       (model_id,)).fetchone()
    print(f"registered model {model_id} (version {row[0]}, active={bool(row[3])})")
    print(f"  file: {row[1]}")
    print("  metrics:", json.dumps(json.loads(row[2]), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
