"""Applies common/db/schema.sql to a SQLite database. Idempotent -- safe to call on every
service start (FR-11.1)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 1

EXPECTED_TABLES = [
    "admin_user", "host", "model_package", "calibration_state", "flow_record",
    "evidence", "verdict", "block_entry", "allowlist_entry", "config_setting",
    "component_event", "audit_log",
]


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()
    actual_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if actual_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"schema version mismatch: expected {SCHEMA_VERSION}, got {actual_version}"
        )


def connect(db_path: str, check_same_thread: bool = True) -> sqlite3.Connection:
    """check_same_thread=False is for the one caller that genuinely shares a single connection
    across threads (services/dashboard: a FastAPI worker-threadpool thread plus its own background
    consumer/heartbeat threads) -- every other service here is single-threaded per connection, so
    the default stays True, matching sqlite3's own safety default, for everyone else."""
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn
