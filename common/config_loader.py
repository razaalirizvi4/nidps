"""Loads defaults into config_setting on first run and provides typed get/update access
backed by the database (FR-10.3, FR-10.6)."""
from __future__ import annotations

import sqlite3
from typing import Union

from common.config_schema import CONFIG_KEYS, CONFIG_KEYS_BY_NAME, validate_value
from common.schemas import utc_now_iso

Number = Union[int, float]


def seed_defaults(conn: sqlite3.Connection) -> None:
    for spec in CONFIG_KEYS:
        conn.execute(
            """INSERT OR IGNORE INTO config_setting
               (setting_key, value, default_value, min_value, max_value)
               VALUES (?, ?, ?, ?, ?)""",
            (
                spec.key,
                str(spec.default),
                str(spec.default),
                str(spec.min_value) if spec.min_value is not None else None,
                str(spec.max_value) if spec.max_value is not None else None,
            ),
        )
    conn.commit()


def _cast(key: str, raw: str):
    spec = CONFIG_KEYS_BY_NAME[key]
    if spec.value_type is bool:
        return raw in ("True", "true", "1")
    return spec.value_type(raw)


def get(conn: sqlite3.Connection, key: str) -> Union[Number, str, bool]:
    row = conn.execute(
        "SELECT value FROM config_setting WHERE setting_key = ?", (key,)
    ).fetchone()
    if row is None:
        raise KeyError(key)
    return _cast(key, row[0])


_THRESHOLD_ORDER = ("fusion.theta_c", "fusion.theta_alert", "fusion.theta_block")


def _check_threshold_order(conn: sqlite3.Connection, key: str, value) -> None:
    """theta_block > theta_alert > theta_c must always hold, or a class could BLOCK at a lower
    confidence than it would ALERT. Changing one threshold is checked against the other two."""
    if key not in _THRESHOLD_ORDER:
        return
    values = {k: get(conn, k) for k in _THRESHOLD_ORDER}
    values[key] = value
    low, mid, high = (values[k] for k in _THRESHOLD_ORDER)
    if not low < mid < high:
        raise ValueError(
            f"{key}={value} breaks the required order theta_c < theta_alert < theta_block "
            f"(would be {low}, {mid}, {high})"
        )


def update(conn: sqlite3.Connection, key: str, value, user_id: int | None = None) -> None:
    validate_value(key, value)
    _check_threshold_order(conn, key, value)
    old = conn.execute(
        "SELECT value FROM config_setting WHERE setting_key = ?", (key,)
    ).fetchone()
    if old is None:
        raise KeyError(key)
    conn.execute(
        "UPDATE config_setting SET value = ?, updated_by = ?, updated_at = ? WHERE setting_key = ?",
        (str(value), user_id, utc_now_iso(), key),
    )
    conn.execute(
        """INSERT INTO audit_log (user_id, action, target, old_value, new_value, timestamp)
           VALUES (?, 'CONFIG_CHANGE', ?, ?, ?, ?)""",
        (user_id, key, old[0], str(value), utc_now_iso()),
    )
    conn.commit()
