import sqlite3

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
