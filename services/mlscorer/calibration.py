"""Algorithm 5.4: per-network anomaly threshold calibration. CalibrationState.recalibrate() is
the pure math (lines 6-11) given an already-filtered score sample. recalibrate_if_due() is the
DB-aware wrapper that performs lines 2-5's filtering, computes u_max from the same local sample
(a documented extension -- see Global Constraints), and writes the new calibration_state row.
FR-13.2 scope note: this implements the recalibration logic only; a later systemd-timer phase
calls recalibrate_if_due() on a weekly schedule.

Note (I12): SignatureDetector.ingestEveAlert() (Task 15) always sets Evidence.flow_id = None,
so the `alerted_flow_ids` exclusion below is permanently empty in practice. As a host-level
fallback, recalibrate_if_due() also excludes every flow belonging to a host that has ANY L1
evidence row in the calibration window, regardless of that row's flow_id."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from common import config_loader
from common.schemas import utc_now_iso
from services.flowextract.features import FEATURE_NAMES

ANOMALY_TAU_GLOBAL_BOOTSTRAP = 0.6
_FWD_BYTES_IDX = FEATURE_NAMES.index("total_fwd_bytes")


def _percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return ordered[int(k)]
    return ordered[int(f)] * (c - k) + ordered[int(c)] * (k - f)


def _is_due(last_computed_at: str, interval_days: int, now_iso: str) -> bool:
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    last = datetime.strptime(last_computed_at, fmt).replace(tzinfo=timezone.utc)
    now = datetime.strptime(now_iso, fmt).replace(tzinfo=timezone.utc)
    return (now - last).days >= interval_days


@dataclass
class CalibrationState:
    threshold: float
    global_threshold: float
    computed_at: str
    sample_count: int
    u_max: Optional[int] = None

    def recalibrate(
        self, scores: list, percentile: float, min_samples: int, max_shift: float
    ) -> "CalibrationState":
        if len(scores) < min_samples:
            new_threshold = self.global_threshold
        else:
            local = _percentile(scores, percentile)
            new_threshold = min(
                max(local, self.global_threshold - max_shift), self.global_threshold + max_shift
            )
        return CalibrationState(
            threshold=new_threshold,
            global_threshold=self.global_threshold,
            computed_at=utc_now_iso(),
            sample_count=len(scores),
            u_max=self.u_max,
        )


def load_calibration_state(conn, model_id: int) -> CalibrationState:
    """Reads the most recent calibration_state row for a model back into a CalibrationState.
    Previously there was no reader at all for this table (I14); falls back to the bootstrap
    global threshold when no row exists yet for this model_id."""
    row = conn.execute(
        """SELECT tau, tau_global, created_at, sample_count, u_max
           FROM calibration_state WHERE model_id = ?
           ORDER BY created_at DESC LIMIT 1""",
        (model_id,),
    ).fetchone()
    if row is None:
        return CalibrationState(
            threshold=ANOMALY_TAU_GLOBAL_BOOTSTRAP,
            global_threshold=ANOMALY_TAU_GLOBAL_BOOTSTRAP,
            computed_at=utc_now_iso(),
            sample_count=0,
            u_max=None,
        )
    tau, tau_global, created_at, sample_count, u_max = row
    return CalibrationState(
        threshold=tau, global_threshold=tau_global, computed_at=created_at,
        sample_count=sample_count, u_max=u_max,
    )


def recalibrate_if_due(
    conn,
    score_fn: Callable,
    model_id: int,
    current_state: CalibrationState,
    window_start_iso: str,
    window_end_iso: str,
    now_iso: Optional[str] = None,
) -> CalibrationState:
    now_iso = now_iso or utc_now_iso()
    interval_days = config_loader.get(conn, "anomaly.recalibration_interval_days")
    if not _is_due(current_state.computed_at, interval_days, now_iso):
        return current_state

    percentile = config_loader.get(conn, "anomaly.calibration_percentile")
    min_samples = config_loader.get(conn, "anomaly.calibration_min_samples")
    max_shift = config_loader.get(conn, "anomaly.calibration_max_shift")
    u_max_percentile = config_loader.get(conn, "exfil.u_max_percentile")

    rows = conn.execute(
        "SELECT flow_id, host_id, features FROM flow_record WHERE start_time >= ? AND start_time < ?",
        (window_start_iso, window_end_iso),
    ).fetchall()
    alerted_flow_ids = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT flow_id FROM evidence WHERE layer = 'L1' AND flow_id IS NOT NULL"
        ).fetchall()
    }
    # Host-level fallback (I12): SignatureDetector never populates flow_id on its evidence, so
    # alerted_flow_ids above is always empty in practice -- exclude by host instead.
    alerted_host_ids = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT host_id FROM evidence WHERE layer = 'L1' AND host_id IS NOT NULL"
        ).fetchall()
    }
    blocked_host_ids = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT host_id FROM block_entry WHERE status = 'ACTIVE'"
        ).fetchall()
    }

    scores = []
    segment_bytes = []
    for flow_id, host_id, features_json in rows:
        if flow_id in alerted_flow_ids or host_id in blocked_host_ids or host_id in alerted_host_ids:
            continue
        values = json.loads(features_json)
        scores.append(score_fn(values))
        segment_bytes.append(values[_FWD_BYTES_IDX])

    u_max = int(_percentile(segment_bytes, u_max_percentile)) if segment_bytes else current_state.u_max
    new_state = current_state.recalibrate(scores, percentile, min_samples, max_shift)
    new_state.u_max = u_max

    conn.execute(
        """INSERT INTO calibration_state
               (model_id, tau, tau_global, percentile, sample_count, u_max, window_start,
                window_end, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            model_id, new_state.threshold, new_state.global_threshold, percentile,
            new_state.sample_count, u_max, window_start_iso, window_end_iso, new_state.computed_at,
        ),
    )
    conn.commit()
    return new_state
