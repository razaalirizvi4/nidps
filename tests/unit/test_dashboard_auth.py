import pytest

from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.dashboard.auth import authenticate, create_admin_user, hash_password, verify_password


def test_hash_password_produces_verifiable_hash():
    stored = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", stored) is True


def test_verify_password_rejects_wrong_password():
    stored = hash_password("correct horse battery staple")

    assert verify_password("wrong password", stored) is False


def test_two_hashes_of_the_same_password_differ_by_salt():
    assert hash_password("same") != hash_password("same")


def test_create_admin_user_inserts_row_with_hashed_password():
    conn = connect(":memory:")

    user_id = create_admin_user(conn, "admin", "s3cret-password")

    row = conn.execute(
        "SELECT username, password_hash, failed_attempts FROM admin_user WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    assert row[0] == "admin"
    assert row[1] != "s3cret-password"
    assert row[2] == 0


def test_create_admin_user_rejects_duplicate_username():
    conn = connect(":memory:")
    create_admin_user(conn, "admin", "first-password")

    with pytest.raises(ValueError):
        create_admin_user(conn, "admin", "second-password")


def _config_get(conn):
    def get(key):
        from common.config_loader import get as _get

        return _get(conn, key)

    return get


def test_authenticate_succeeds_with_correct_credentials():
    conn = connect(":memory:")
    seed_defaults(conn)
    user_id = create_admin_user(conn, "admin", "correct-password")

    result = authenticate(conn, _config_get(conn), "admin", "correct-password")

    assert result.ok is True
    assert result.user_id == user_id


def test_authenticate_fails_with_generic_reason_for_wrong_password():
    conn = connect(":memory:")
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")

    result = authenticate(conn, _config_get(conn), "admin", "wrong-password")

    assert result.ok is False
    assert result.reason == "invalid_credentials"


def test_authenticate_fails_with_same_generic_reason_for_unknown_username():
    conn = connect(":memory:")
    seed_defaults(conn)

    result = authenticate(conn, _config_get(conn), "nobody", "anything")

    assert result.ok is False
    assert result.reason == "invalid_credentials"


def test_authenticate_locks_account_after_configured_failed_attempts():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "auth.lockout_attempts", 3)
    create_admin_user(conn, "admin", "correct-password")

    for _ in range(3):
        authenticate(conn, _config_get(conn), "admin", "wrong-password")

    result = authenticate(conn, _config_get(conn), "admin", "correct-password")

    assert result.ok is False
    assert result.reason == "locked"


def test_authenticate_unlocks_after_lockout_duration_elapses():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "auth.lockout_attempts", 3)  # 3 is the configured minimum (config_schema.py)
    update(conn, "auth.lockout_duration_s", 300)
    create_admin_user(conn, "admin", "correct-password")

    for _ in range(3):
        authenticate(
            conn, _config_get(conn), "admin", "wrong-password",
            now_fn=lambda: "2026-01-01T00:00:00.000000Z",
        )
    locked_out = authenticate(
        conn, _config_get(conn), "admin", "correct-password",
        now_fn=lambda: "2026-01-01T00:00:01.000000Z",
    )
    after_window = authenticate(
        conn, _config_get(conn), "admin", "correct-password",
        now_fn=lambda: "2026-01-01T00:05:01.000000Z",
    )

    assert locked_out.ok is False
    assert locked_out.reason == "locked"
    assert after_window.ok is True


def test_authenticate_resets_failed_attempts_on_success():
    conn = connect(":memory:")
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")

    authenticate(conn, _config_get(conn), "admin", "wrong-password")
    authenticate(conn, _config_get(conn), "admin", "correct-password")

    row = conn.execute("SELECT failed_attempts FROM admin_user WHERE username = 'admin'").fetchone()
    assert row[0] == 0
