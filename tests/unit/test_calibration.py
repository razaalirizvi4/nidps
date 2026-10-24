# tests/unit/test_calibration.py
import json
import math

from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.persistence import upsert_host
from services.mlscorer.calibration import CalibrationState, recalibrate_if_due

_FWD_BYTES_IDX = FEATURE_NAMES.index("total_fwd_bytes")


def test_recalibrate_falls_back_to_global_when_too_few_samples():
    state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    new_state = state.recalibrate([0.1, 0.2, 0.3], percentile=99.5, min_samples=10, max_shift=0.15)

    assert new_state.threshold == 0.6
    assert new_state.sample_count == 3


def test_recalibrate_clips_local_percentile_to_max_shift():
    state = CalibrationState(
        threshold=0.5, global_threshold=0.5, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    new_state = state.recalibrate([0.95] * 50, percentile=99.5, min_samples=10, max_shift=0.15)

    assert math.isclose(new_state.threshold, 0.65)


def _insert_flow(conn, host_id: int, start_time: str, fwd_bytes: float) -> int:
    values = [0.0] * len(FEATURE_NAMES)
    values[_FWD_BYTES_IDX] = fwd_bytes
    cursor = conn.execute(
        """INSERT INTO flow_record (host_id, src_ip, dst_ip, src_port, dst_port, protocol,
               start_time, end_time, segment_no, features, extractor_version)
           VALUES (?, '10.0.0.5', '1.2.3.4', 1, 2, 'TCP', ?, ?, 0, ?, 'dev')""",
        (host_id, start_time, start_time, json.dumps(values)),
    )
    conn.commit()
    return cursor.lastrowid


def _insert_model_package(conn) -> int:
    cursor = conn.execute(
        """INSERT INTO model_package (model_type, version, file_path, feature_list_hash,
               extractor_version, is_active)
           VALUES ('IFOREST', 'dev', 'dev', 'dev', 'dev', 1)"""
    )
    conn.commit()
    return cursor.lastrowid


def test_recalibrate_if_due_excludes_alerted_and_blocked_flows_and_writes_row():
    conn = connect(":memory:")
    seed_defaults(conn)
    # Bypass validation to set min_samples = 1 for testing
    conn.execute(
        "UPDATE config_setting SET value = '1' WHERE setting_key = 'anomaly.calibration_min_samples'"
    )
    conn.commit()
    model_id = _insert_model_package(conn)
    host_id = upsert_host(conn, "10.0.0.5")
    other_host_id = upsert_host(conn, "10.0.0.9")

    eligible_flow_id = _insert_flow(conn, host_id, "2026-01-05T00:00:00.000000Z", 1000.0)
    alerted_flow_id = _insert_flow(conn, host_id, "2026-01-05T00:00:01.000000Z", 5000.0)
    blocked_flow_id = _insert_flow(conn, other_host_id, "2026-01-05T00:00:02.000000Z", 9000.0)

    conn.execute(
        "INSERT INTO evidence (flow_id, host_id, layer, evidence_type, weight) "
        "VALUES (?, ?, 'L1', 'SIGNATURE', 1.0)",
        (alerted_flow_id, host_id),
    )
    conn.execute(
        "INSERT INTO verdict (flow_id, host_id, decision, layers, explanation) "
        "VALUES (?, ?, 'BLOCK', '[]', 'x')",
        (blocked_flow_id, other_host_id),
    )
    verdict_id = conn.execute(
        "SELECT verdict_id FROM verdict WHERE flow_id = ?", (blocked_flow_id,)
    ).fetchone()[0]
    conn.execute(
        """INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time,
               expires_at, status)
           VALUES (?, ?, 1, 300, '2026-01-05T00:00:02.000000Z', '2026-01-05T00:05:02.000000Z', 'ACTIVE')""",
        (other_host_id, verdict_id),
    )
    conn.commit()

    current_state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    scored = []

    def score_fn(values):
        scored.append(values)
        return 0.9

    new_state = recalibrate_if_due(
        conn, score_fn, model_id, current_state,
        window_start_iso="2026-01-01T00:00:00.000000Z", window_end_iso="2026-01-10T00:00:00.000000Z",
        now_iso="2026-01-10T00:00:00.000000Z",
    )

    assert new_state.sample_count == 1  # only the eligible flow
    assert len(scored) == 1
    assert new_state.threshold == 0.75  # local percentile 0.9 clipped to [0.45, 0.75]
    assert new_state.u_max == 1000
    assert conn.execute("SELECT COUNT(*) FROM calibration_state").fetchone()[0] == 1


def test_recalibrate_if_due_returns_unchanged_state_when_not_due():
    conn = connect(":memory:")
    seed_defaults(conn)
    model_id = _insert_model_package(conn)
    current_state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2026-01-09T00:00:00.000000Z", sample_count=5
    )

    result = recalibrate_if_due(
        conn, lambda v: 0.5, model_id, current_state,
        window_start_iso="2026-01-01T00:00:00.000000Z", window_end_iso="2026-01-10T00:00:00.000000Z",
        now_iso="2026-01-10T00:00:00.000000Z",
    )

    assert result is current_state
