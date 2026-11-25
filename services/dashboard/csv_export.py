"""CSV export of alerts and blocks for a chosen time period (FR-11.3). ISO 8601 strings compare
lexicographically, so range filtering never converts to epoch floats -- same convention as Phase
2's calibration window filter (services/mlscorer/calibration.py)."""
from __future__ import annotations

import csv
import io
import sqlite3


def export_alerts_csv(conn: sqlite3.Connection, start_iso: str, end_iso: str) -> str:
    rows = conn.execute(
        """SELECT verdict.created_at, host.ip_address, verdict.decision, verdict.attack_class,
                  verdict.layers, verdict.explanation
           FROM verdict JOIN host ON host.host_id = verdict.host_id
           WHERE verdict.created_at >= ? AND verdict.created_at < ?
           ORDER BY verdict.created_at""",
        (start_iso, end_iso),
    ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["created_at", "host_ip", "decision", "attack_class", "layers", "explanation"])
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def export_blocks_csv(conn: sqlite3.Connection, start_iso: str, end_iso: str) -> str:
    rows = conn.execute(
        """SELECT block_entry.start_time, host.ip_address, block_entry.duration_s,
                  block_entry.offence_count, block_entry.status, block_entry.expires_at,
                  block_entry.released_at
           FROM block_entry JOIN host ON host.host_id = block_entry.host_id
           WHERE block_entry.start_time >= ? AND block_entry.start_time < ?
           ORDER BY block_entry.start_time""",
        (start_iso, end_iso),
    ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["start_time", "ip_address", "duration_s", "offence_count", "status", "expires_at", "released_at"]
    )
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
