import pytest

from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.dashboard.auth import create_admin_user
from services.dashboard.config_api import SETTINGS_TABS, get_tab, update_setting


def test_every_config_key_is_assigned_to_exactly_one_tab():
    from common.config_schema import CONFIG_KEYS_BY_NAME

    assigned = [key for keys in SETTINGS_TABS.values() for key in keys]
    assert sorted(assigned) == sorted(CONFIG_KEYS_BY_NAME.keys())
    assert len(assigned) == len(set(assigned))  # no key in two tabs


def test_get_tab_returns_detection_layers_with_current_values():
    conn = connect(":memory:")
    seed_defaults(conn)

    rows = get_tab(conn, "detection_layers")

    keys = {row["key"] for row in rows}
    assert "detection.layer1_enabled" in keys
    layer1 = next(row for row in rows if row["key"] == "detection.layer1_enabled")
    assert layer1["value"] is True
    assert layer1["default"] is True


def test_get_tab_raises_for_unknown_tab():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(KeyError):
        get_tab(conn, "no-such-tab")


def test_update_setting_writes_through_to_config_loader():
    conn = connect(":memory:")
    seed_defaults(conn)
    user_id = create_admin_user(conn, "admin", "password")

    update_setting(conn, "risk.block_threshold", 7.0, user_id=user_id)

    rows = get_tab(conn, "thresholds")
    row = next(r for r in rows if r["key"] == "risk.block_threshold")
    assert row["value"] == 7.0


def test_update_setting_rejects_out_of_range_value():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(ValueError):
        update_setting(conn, "risk.block_threshold", 999.0, user_id=1)
