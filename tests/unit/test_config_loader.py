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


def test_threshold_order_is_enforced():
    conn = connect(":memory:")
    seed_defaults(conn)  # theta_c 0.50 < theta_alert 0.70 < theta_block 0.90

    with pytest.raises(ValueError):
        update(conn, "fusion.theta_block", 0.65)  # below theta_alert
    with pytest.raises(ValueError):
        update(conn, "fusion.theta_alert", 0.95)  # above theta_block
    with pytest.raises(ValueError):
        update(conn, "fusion.theta_c", 0.70)  # equal to theta_alert
    assert (get(conn, "fusion.theta_block"), get(conn, "fusion.theta_alert")) == (0.90, 0.70)
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0


def test_thresholds_can_be_moved_together_in_a_valid_order():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "fusion.theta_block", 0.95)
    update(conn, "fusion.theta_alert", 0.85)
    update(conn, "fusion.theta_c", 0.60)
    assert (get(conn, "fusion.theta_c"), get(conn, "fusion.theta_alert")) == (0.60, 0.85)
