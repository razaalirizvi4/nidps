"""FR-13.3: deletes flow_record rows older than the retention window. The cutoff computed here is
a narrow, deliberate exception to "only utc_now_iso() stamps now" -- it is an ephemeral comparison
threshold for one DELETE statement, never persisted anywhere, and uses the exact same
'%Y-%m-%dT%H:%M:%S.%fZ' format utc_now_iso() uses so string comparison against the TEXT end_time
column sorts correctly."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def purge_old_flows(conn, retention_days: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    cursor = conn.execute("DELETE FROM flow_record WHERE end_time < ?", (cutoff,))
    conn.commit()
    return cursor.rowcount
