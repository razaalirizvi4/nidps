"""Password hashing (FR-9.1) and the admin_user table this plan owns exclusively. PBKDF2-HMAC-
SHA256 via stdlib hashlib -- no bcrypt/argon2 dependency needed for a single-admin device."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from common.schemas import utc_now_iso

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 210_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALGORITHM}${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations_s, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if algorithm != _ALGORITHM:
        return False
    iterations = int(iterations_s)
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def create_admin_user(conn: sqlite3.Connection, username: str, password: str) -> int:
    existing = conn.execute(
        "SELECT user_id FROM admin_user WHERE username = ?", (username,)
    ).fetchone()
    if existing is not None:
        raise ValueError(f"admin_user {username!r} already exists")
    cursor = conn.execute(
        "INSERT INTO admin_user (username, password_hash, failed_attempts, created_at) "
        "VALUES (?, ?, 0, ?)",
        (username, hash_password(password), utc_now_iso()),
    )
    conn.commit()
    return cursor.lastrowid


@dataclass
class AuthResult:
    ok: bool
    user_id: Optional[int] = None
    reason: Optional[str] = None


def _add_seconds(iso_ts: str, seconds: int) -> str:
    dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (dt + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def authenticate(
    conn: sqlite3.Connection,
    config_get: Callable[[str], object],
    username: str,
    password: str,
    now_fn: Callable[[], str] = utc_now_iso,
) -> AuthResult:
    """FR-9.1: the same generic reason is returned whether the username doesn't exist or the
    password is wrong, so a login form never reveals which field was incorrect."""
    row = conn.execute(
        "SELECT user_id, password_hash, failed_attempts, locked_until FROM admin_user "
        "WHERE username = ?",
        (username,),
    ).fetchone()
    now = now_fn()

    if row is None:
        return AuthResult(ok=False, reason="invalid_credentials")

    user_id, password_hash, failed_attempts, locked_until = row
    if locked_until is not None and now < locked_until:
        return AuthResult(ok=False, reason="locked")

    if not verify_password(password, password_hash):
        failed_attempts += 1
        lockout_attempts = int(config_get("auth.lockout_attempts"))
        new_locked_until = None
        if failed_attempts >= lockout_attempts:
            lockout_duration_s = int(config_get("auth.lockout_duration_s"))
            new_locked_until = _add_seconds(now, lockout_duration_s)
        conn.execute(
            "UPDATE admin_user SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
            (failed_attempts, new_locked_until, user_id),
        )
        conn.commit()
        return AuthResult(ok=False, reason="locked" if new_locked_until else "invalid_credentials")

    conn.execute(
        "UPDATE admin_user SET failed_attempts = 0, locked_until = NULL, last_login = ? "
        "WHERE user_id = ?",
        (now, user_id),
    )
    conn.commit()
    return AuthResult(ok=True, user_id=user_id)
