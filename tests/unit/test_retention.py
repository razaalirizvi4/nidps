from datetime import datetime, timedelta, timezone

from common.db.migrate import connect
from services.flowextract.persistence import upsert_host
from services.flowextract.retention import purge_old_flows


def _insert_flow(conn, host_id: int, end_time_iso: str) -> None:
    conn.execute(
        """INSERT INTO flow_record
               (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
                segment_no, features, extractor_version)
           VALUES (?, '10.0.0.5', '1.2.3.4', 1, 2, 'TCP', ?, ?, 0, '[]', 'dev')""",
        (host_id, end_time_iso, end_time_iso),
    )
    conn.commit()


def test_purge_deletes_only_rows_older_than_retention_window():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    now = datetime.now(timezone.utc)
    old_iso = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    recent_iso = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_flow(conn, host_id, old_iso)
    _insert_flow(conn, host_id, recent_iso)

    deleted = purge_old_flows(conn, retention_days=7)

    assert deleted == 1
    remaining = conn.execute("SELECT end_time FROM flow_record").fetchall()
    assert remaining == [(recent_iso,)]


def test_purge_returns_zero_when_nothing_is_old():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    recent_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_flow(conn, host_id, recent_iso)

    assert purge_old_flows(conn, retention_days=7) == 0
