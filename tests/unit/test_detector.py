from common.detector import Detector
from common.schemas import ComponentHealth, HealthState


class DummyDetector(Detector):
    name = "dummy"

    def analyse(self, item):
        return None

    def heartbeat(self):
        return ComponentHealth(name=self.name, state=HealthState.NORMAL, last_heartbeat="now")


def test_dummy_detector_implements_interface():
    detector = DummyDetector()
    assert detector.analyse("anything") is None
    assert detector.heartbeat().state == HealthState.NORMAL


def test_detector_cannot_be_instantiated_directly():
    import pytest

    with pytest.raises(TypeError):
        Detector()
