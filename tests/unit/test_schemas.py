from common.schemas import FEATURE_COUNT, SCHEMA_VERSION, FlowFeatures, Layer


def test_flow_features_valid_when_length_and_version_match():
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)
    assert features.validate() is True


def test_flow_features_invalid_when_length_wrong():
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * 10)
    assert features.validate() is False


def test_flow_features_invalid_when_schema_version_wrong():
    features = FlowFeatures(schema_version="0.9", values=[0.0] * FEATURE_COUNT)
    assert features.validate() is False


def test_layer_values_match_db_check_constraint():
    assert {l.value for l in Layer} == {"L1", "ARP", "L2", "L3", "HOST"}
