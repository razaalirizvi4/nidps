"""Layer 2 evaluation: score held-out flows with the registered Isolation Forest and report how it
behaves on traffic it was never trained on.

    python -m training.evaluate_iforest --db data/nidps.sqlite3 \\
        --benign data/features/selfcollected/* [--attack data/features/<attack run>/*]

Benign sets give the false-alarm rate. Attack sets (flows known to be malicious) give the
detection rate. Each is measured at two thresholds: the global tau_g the model shipped with, and
the per-network tau that Algorithm 5.4 would settle on after watching the same benign traffic
(Section 5.5.3 compares exactly these two). Nothing here trains or changes the model."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Sequence

import numpy as np

from common import config_loader
from services.mlscorer.anomaly import load_active_model
from services.mlscorer.calibration import CalibrationState, load_calibration_state
from training.train_iforest import load_feature_sets, score_matrix


def load_flow_meta(dirs: Sequence) -> list:
    """flows.csv rows from each feature directory, in the same order load_feature_sets stacks
    the matrices, so row i of the matrix is meta[i]."""
    rows: list = []
    for d in dirs:
        path = Path(d) / "flows.csv"
        if not path.exists():  # shared copies of the data may ship the numbers without addresses
            return []
        with open(path, newline="") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


def calibrated_threshold(
    state: CalibrationState, scores: np.ndarray, percentile: float, min_samples: int, max_shift: float
) -> float:
    """What the device would set tau to after observing these scores (Algorithm 5.4)."""
    return state.recalibrate(list(map(float, scores)), percentile, min_samples, max_shift).threshold


def rate_at(scores: np.ndarray, tau: float) -> dict:
    flagged = int((scores > tau).sum())
    return {"tau": float(tau), "flagged": flagged, "rate": flagged / len(scores) if len(scores) else 0.0}


def summarise(scores: np.ndarray, thresholds: dict) -> dict:
    return {
        "flows": int(len(scores)),
        "score_p50": float(np.percentile(scores, 50)),
        "score_p99": float(np.percentile(scores, 99)),
        "score_max": float(scores.max()),
        "at": {name: rate_at(scores, tau) for name, tau in thresholds.items()},
    }


def top_flagged(scores: np.ndarray, tau: float, meta: list, n: int = 8) -> list:
    """The destinations that account for most of the flagged flows, so false alarms can be
    traced to a service instead of being a bare percentage."""
    counts: Counter = Counter()
    for score, row in zip(scores, meta):
        if score > tau:
            counts[(row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"])] += 1
    return [{"src": k[0], "dst": k[1], "dst_port": k[2], "protocol": k[3], "flows": v}
            for k, v in counts.most_common(n)]


def evaluate(conn, benign_dirs: Sequence, attack_dirs: Sequence = ()) -> dict:
    """Always evaluates the active model with its own calibration row."""
    model_id, model = load_active_model(conn)
    state = load_calibration_state(conn, model_id)
    percentile = config_loader.get(conn, "anomaly.calibration_percentile")
    min_samples = config_loader.get(conn, "anomaly.calibration_min_samples")
    max_shift = config_loader.get(conn, "anomaly.calibration_max_shift")

    X_b, _ = load_feature_sets(benign_dirs)
    meta = load_flow_meta(benign_dirs)
    if len(meta) != len(X_b):
        meta = []  # no addresses available: the report just omits the flagged-destination list
    s_b = score_matrix(model, X_b)
    tau_local = calibrated_threshold(state, s_b, percentile, min_samples, max_shift)
    thresholds = {"global": state.global_threshold, "calibrated": tau_local}

    report = {
        "model_id": model_id,
        "tau_global": state.global_threshold,
        "tau_calibrated": tau_local,
        "benign": summarise(s_b, thresholds),
        "benign_top_flagged_at_global": top_flagged(s_b, state.global_threshold, meta),
    }
    if attack_dirs:
        X_a, _ = load_feature_sets(attack_dirs)
        report["attack"] = summarise(score_matrix(model, X_a), thresholds)
    return report


def print_report(report: dict) -> None:
    b = report["benign"]
    print(f"model {report['model_id']}: tau_global={report['tau_global']:.3f}, "
          f"tau_calibrated={report['tau_calibrated']:.3f}")
    print(f"\nBENIGN ({b['flows']:,} flows)  score p50={b['score_p50']:.3f} "
          f"p99={b['score_p99']:.3f} max={b['score_max']:.3f}")
    for name, r in b["at"].items():
        print(f"  false alarms at {name:<10} tau={r['tau']:.3f}: {r['flagged']:,} flows ({r['rate']:.2%})")
    if report["benign_top_flagged_at_global"]:
        print("  most-flagged destinations at global tau:")
        for t in report["benign_top_flagged_at_global"]:
            print(f"    {t['src']} -> {t['dst']}:{t['dst_port']} {t['protocol']}: {t['flows']:,}")
    if "attack" in report:
        a = report["attack"]
        print(f"\nATTACK ({a['flows']:,} flows)  score p50={a['score_p50']:.3f} max={a['score_max']:.3f}")
        for name, r in a["at"].items():
            print(f"  detected at {name:<10} tau={r['tau']:.3f}: {r['flagged']:,} flows ({r['rate']:.2%})")


def _expand(patterns: Sequence) -> list:
    import glob

    out: list = []
    for p in patterns:
        out.extend(sorted(glob.glob(p)) or [p])
    return out


def main(argv=None) -> int:
    from common.db.migrate import connect

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--db", required=True)
    parser.add_argument("--benign", nargs="+", required=True, help="feature dirs of benign test flows")
    parser.add_argument("--attack", nargs="+", default=[], help="feature dirs of known-attack flows")
    parser.add_argument("--json", default=None, help="also write the report to this file")
    args = parser.parse_args(argv)

    conn = connect(args.db)
    config_loader.seed_defaults(conn)
    report = evaluate(conn, _expand(args.benign), _expand(args.attack))
    print_report(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
