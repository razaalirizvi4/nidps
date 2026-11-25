"""Grouped read/update view over common.config_loader (FR-10.1-10.3), matching the Settings
screen's four tabs: Detection Layers, Thresholds, Prevention & Failure, Rules/Calibration/Models.
The spec's mockup names the tabs but not the key-to-tab mapping -- this grouping is this service's
own design choice, documented here rather than left implicit in route code. Exhaustiveness against
common.config_schema.CONFIG_KEYS_BY_NAME is enforced by
test_every_config_key_is_assigned_to_exactly_one_tab, so a new config key added there without
updating this mapping fails a test instead of silently becoming unreachable from the Settings
screen."""
from __future__ import annotations

import sqlite3

from common.config_loader import get as config_get
from common.config_loader import update as config_update
from common.config_schema import CONFIG_KEYS_BY_NAME

SETTINGS_TABS: dict[str, list[str]] = {
    "detection_layers": [
        "detection.layer1_enabled",
        "detection.layer2_enabled",
        "detection.layer3_enabled",
        "network.active_timeout_s",
        "network.idle_timeout_s",
    ],
    "thresholds": [
        "anomaly.n_estimators",
        "anomaly.subsample_size",
        "exfil.ewma_alpha",
        "exfil.bucket_seconds",
        "exfil.k_std",
        "exfil.u_max_percentile",
        "beacon.min_connections",
        "beacon.cv_threshold",
        "fusion.theta_block",
        "fusion.theta_alert",
        "fusion.theta_c",
        "risk.half_life_s",
        "risk.block_threshold",
        "risk.weight_signature",
        "risk.weight_anomaly",
        "risk.weight_class",
        "risk.weight_exfil",
        "risk.weight_beacon",
    ],
    "prevention_and_failure": [
        "enforcement.base_block_s",
        "enforcement.max_block_s",
        "enforcement.rate_limit_per_minute",
        "failure_mode",
        "watchdog.heartbeat_interval_s",
        "watchdog.missed_heartbeats_threshold",
        "watchdog.cpu_high_watermark",
        "watchdog.cpu_low_watermark",
        "retention.flow_days",
        "auth.lockout_attempts",
        "auth.lockout_duration_s",
    ],
    "rules_calibration_models": [
        "anomaly.calibration_window_hours",
        "anomaly.calibration_percentile",
        "anomaly.calibration_min_samples",
        "anomaly.calibration_max_shift",
        "anomaly.recalibration_interval_days",
        "rules.update_interval_hours",
    ],
}


def get_tab(conn: sqlite3.Connection, tab: str) -> list[dict]:
    if tab not in SETTINGS_TABS:
        raise KeyError(f"Unknown settings tab: {tab!r}")
    rows = []
    for key in SETTINGS_TABS[tab]:
        spec = CONFIG_KEYS_BY_NAME[key]
        rows.append({
            "key": key,
            "value": config_get(conn, key),
            "default": spec.default,
            "min_value": spec.min_value,
            "max_value": spec.max_value,
        })
    return rows


def update_setting(conn: sqlite3.Connection, key: str, value, user_id: int) -> None:
    config_update(conn, key, value, user_id=user_id)
