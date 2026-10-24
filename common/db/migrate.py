"""Applies common/db/schema.sql to a SQLite database. Idempotent -- safe to call on every
service start (FR-11.1)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

EXPECTED_TABLES = [
    "admin_user", "host", "model_package", "calibration_state", "flow_record",
    "evidence", "verdict", "block_entry", "allowlist_entry", "config_setting",
    "component_event", "audit_log",
]


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn
