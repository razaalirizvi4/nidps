import pytest

from common.config_schema import CONFIG_KEYS_BY_NAME, validate_value


def test_every_key_has_a_default_within_its_own_range():
    for spec in CONFIG_KEYS_BY_NAME.values():
        if spec.min_value is not None:
            assert spec.default >= spec.min_value
        if spec.max_value is not None:
            assert spec.default <= spec.max_value


def test_validate_value_accepts_in_range_value():
    validate_value("risk.block_threshold", 7.0)  # must not raise


def test_validate_value_rejects_out_of_range_value():
    with pytest.raises(ValueError):
        validate_value("risk.block_threshold", 999.0)


def test_validate_value_rejects_wrong_type():
    with pytest.raises(ValueError):
        validate_value("detection.layer1_enabled", "yes")


def test_validate_value_rejects_unknown_key():
    with pytest.raises(KeyError):
        validate_value("no.such.key", 1)


def test_validate_value_rejects_float_for_int_typed_key():
    with pytest.raises(ValueError):
        validate_value("network.active_timeout_s", 10.5)


def test_validate_value_rejects_failure_mode_not_in_allowed_set():
    with pytest.raises(ValueError):
        validate_value("failure_mode", "banana")


def test_validate_value_accepts_failure_mode_in_allowed_set():
    validate_value("failure_mode", "FAIL_CLOSED")  # must not raise
