import csv
import io

from common.db.migrate import connect
from services.dashboard.csv_export import export_alerts_csv, export_blocks_csv


def test_export_alerts_csv_includes_header_and_rows_in_range():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, attack_class, explanation, created_at) "
        "VALUES (?, 'ALERT', '[\"L2\"]', 'ANOMALY', 'score above tau', '2026-03-10T00:00:00Z')",
        (host_id,),
    )
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, attack_class, explanation, created_at) "
        "VALUES (?, 'ALERT', '[\"L2\"]', 'ANOMALY', 'outside range', '2026-05-01T00:00:00Z')",
        (host_id,),
    )
    conn.commit()

    csv_text = export_alerts_csv(conn, "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z")

    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert reader[0]["explanation"] == "score above tau"
    assert reader[0]["host_ip"] == "10.0.0.5"


def test_export_blocks_csv_includes_header_and_rows_in_range():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.8', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, explanation, created_at) "
        "VALUES (?, 'BLOCK', '[]', 'x', '2026-03-10T00:00:00Z')",
        (host_id,),
    )
    verdict_id = conn.execute("SELECT verdict_id FROM verdict").fetchone()[0]
    conn.execute(
        "INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time, "
        "expires_at, status) VALUES (?, ?, 1, 300, '2026-03-10T00:00:00Z', '2026-03-10T00:05:00Z', 'EXPIRED')",
        (host_id, verdict_id),
    )
    conn.commit()

    csv_text = export_blocks_csv(conn, "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z")

    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert reader[0]["ip_address"] == "10.0.0.8"
    assert reader[0]["status"] == "EXPIRED"
