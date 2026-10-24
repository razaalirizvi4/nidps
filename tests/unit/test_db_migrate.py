import sqlite3

import pytest

from common.db.migrate import EXPECTED_TABLES, connect, migrate


def test_connect_creates_all_tables():
    conn = connect(":memory:")
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    names = {row[0] for row in rows}

    for table in EXPECTED_TABLES:
        assert table in names


def test_migrate_is_idempotent():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    migrate(conn)  # must not raise


def test_host_ip_address_is_unique():
    conn = connect(":memory:")
    conn.execute(
        "INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)"
        )


def test_schema_version_is_set():
    conn = connect(":memory:")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 1
