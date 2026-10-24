import pytest

from common.config_loader import get, seed_defaults, update
from common.db.migrate import connect


def test_seed_defaults_populates_every_key():
    conn = connect(":memory:")
    seed_defaults(conn)

    count = conn.execute("SELECT COUNT(*) FROM config_setting").fetchone()[0]
    assert count > 0
    assert get(conn, "risk.block_threshold") == 6.0


def test_update_rejects_out_of_range_value():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(ValueError):
        update(conn, "risk.block_threshold", 999.0)

    assert get(conn, "risk.block_threshold") == 6.0


def test_update_writes_audit_log():
    conn = connect(":memory:")
    seed_defaults(conn)

    update(conn, "risk.block_threshold", 7.5, user_id=None)

    row = conn.execute(
        "SELECT action, new_value FROM audit_log WHERE target = 'risk.block_threshold'"
    ).fetchone()
    assert row == ("CONFIG_CHANGE", "7.5")
    assert get(conn, "risk.block_threshold") == 7.5


def test_update_on_unseeded_key_raises_and_writes_no_audit_row():
    conn = connect(":memory:")
    # deliberately do NOT call seed_defaults()

    with pytest.raises(KeyError):
        update(conn, "risk.block_threshold", 7.0)

    audit_count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    assert audit_count == 0
