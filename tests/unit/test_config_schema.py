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
