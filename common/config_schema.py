"""Canonical list of every tunable NIDPS setting (FR-10.3), backed by the config_setting table.
The spec leaves most of these numeric values unstated or gives them only as "e.g." examples
(see docs/superpowers/plans/2026-10-10-00-master-roadmap.md for the rationale behind each
default chosen here). Two defaults ARE implied by the spec itself: risk.block_threshold=6.0 and
enforcement.rate_limit_per_minute=10 both match numbers shown in the dashboard mockups
(Figures 4.5 and 4.6)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

Number = Union[int, float]


@dataclass(frozen=True)
class ConfigKey:
    key: str
    value_type: type
    default: Union[Number, str, bool]
    min_value: Optional[Number] = None
    max_value: Optional[Number] = None


CONFIG_KEYS: list[ConfigKey] = [
    ConfigKey("network.active_timeout_s", int, 10, 5, 30),
    ConfigKey("network.idle_timeout_s", int, 30, 10, 120),
    ConfigKey("detection.layer1_enabled", bool, True),
    ConfigKey("detection.layer2_enabled", bool, True),
    ConfigKey("detection.layer3_enabled", bool, True),
    ConfigKey("anomaly.n_estimators", int, 100, 50, 500),
    ConfigKey("anomaly.subsample_size", int, 256, 64, 1024),
    ConfigKey("anomaly.calibration_window_hours", int, 48, 24, 72),
    ConfigKey("anomaly.calibration_percentile", float, 99.5, 90.0, 99.99),
    ConfigKey("anomaly.calibration_min_samples", int, 2000, 100, 100000),
    ConfigKey("anomaly.calibration_max_shift", float, 0.15, 0.0, 0.5),
    ConfigKey("anomaly.recalibration_interval_days", int, 7, 1, 30),
    ConfigKey("exfil.ewma_alpha", float, 0.3, 0.01, 1.0),
    ConfigKey("exfil.bucket_seconds", int, 60, 10, 300),
    ConfigKey("exfil.k_std", float, 4.0, 1.0, 10.0),
    ConfigKey("exfil.u_max_percentile", float, 99.9, 90.0, 99.99),
    ConfigKey("beacon.min_connections", int, 5, 2, 50),
    ConfigKey("beacon.cv_threshold", float, 0.15, 0.01, 1.0),
    ConfigKey("fusion.theta_block", float, 0.90, 0.5, 1.0),
    ConfigKey("fusion.theta_alert", float, 0.70, 0.3, 1.0),
    ConfigKey("fusion.theta_c", float, 0.50, 0.1, 1.0),
    ConfigKey("risk.half_life_s", int, 600, 60, 3600),
    ConfigKey("risk.block_threshold", float, 6.0, 1.0, 20.0),
    ConfigKey("risk.weight_signature", float, 3.0, 0.0, 10.0),
    ConfigKey("risk.weight_anomaly", float, 2.0, 0.0, 10.0),
    ConfigKey("risk.weight_class", float, 2.5, 0.0, 10.0),
    ConfigKey("risk.weight_exfil", float, 2.0, 0.0, 10.0),
    ConfigKey("risk.weight_beacon", float, 2.5, 0.0, 10.0),
    ConfigKey("enforcement.base_block_s", int, 300, 30, 3600),
    ConfigKey("enforcement.max_block_s", int, 86400, 3600, 604800),
    ConfigKey("enforcement.rate_limit_per_minute", int, 10, 1, 1000),
    ConfigKey("watchdog.heartbeat_interval_s", float, 1.0, 0.1, 10.0),
    ConfigKey("watchdog.missed_heartbeats_threshold", int, 3, 1, 10),
    ConfigKey("watchdog.cpu_high_watermark", float, 0.85, 0.5, 1.0),
    ConfigKey("watchdog.cpu_low_watermark", float, 0.60, 0.1, 0.95),
    ConfigKey("retention.flow_days", int, 7, 1, 90),
    ConfigKey("auth.lockout_attempts", int, 5, 3, 10),
    ConfigKey("auth.lockout_duration_s", int, 300, 60, 3600),
    ConfigKey("rules.update_interval_hours", int, 24, 1, 168),
    ConfigKey("failure_mode", str, "FAIL_OPEN"),
]

CONFIG_KEYS_BY_NAME: dict[str, ConfigKey] = {k.key: k for k in CONFIG_KEYS}


def validate_value(key: str, value) -> None:
    spec = CONFIG_KEYS_BY_NAME[key]
    if spec.value_type is bool:
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a bool")
        return
    if spec.value_type in (int, float):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError(f"{key} must be numeric")
        if spec.min_value is not None and value < spec.min_value:
            raise ValueError(f"{key}={value} below min {spec.min_value}")
        if spec.max_value is not None and value > spec.max_value:
            raise ValueError(f"{key}={value} above max {spec.max_value}")
        return
    if spec.value_type is str:
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        return
