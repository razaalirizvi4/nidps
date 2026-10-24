import math

from services.flowextract.welford import WelfordAccumulator


def test_empty_accumulator_defaults():
    acc = WelfordAccumulator()
    assert acc.count == 0
    assert acc.mean == 0.0
    assert acc.variance == 0.0
    assert acc.std == 0.0
    assert acc.minimum == 0.0
    assert acc.maximum == 0.0
    assert acc.total == 0.0


def test_single_value_has_zero_variance():
    acc = WelfordAccumulator()
    acc.add(10.0)
    assert acc.count == 1
    assert acc.mean == 10.0
    assert acc.variance == 0.0
    assert acc.minimum == 10.0
    assert acc.maximum == 10.0
    assert acc.total == 10.0


def test_three_values_match_hand_computed_sample_variance():
    acc = WelfordAccumulator()
    for x in (10.0, 12.0, 14.0):
        acc.add(x)

    assert acc.count == 3
    assert acc.mean == 12.0
    assert math.isclose(acc.variance, 4.0)  # M2=8.0, sample variance = 8.0 / (3-1)
    assert math.isclose(acc.std, 2.0)
    assert acc.minimum == 10.0
    assert acc.maximum == 14.0
    assert acc.total == 36.0
