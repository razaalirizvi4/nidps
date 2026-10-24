import hashlib

from training.selfcollected.attacks.common.ja3 import compute_ja3


def test_compute_ja3_matches_manually_built_string_per_algorithm_5_1():
    # Algorithm 5.1 (ch5.tex §5.3.3): version,ciphers,extensions,groups,point_formats
    # joined with '-' within each field, fields joined with ',', then MD5 hex digest.
    version = 771
    ciphers = [4866, 4867, 4865]
    extensions = [0, 23, 65281, 10, 11, 35, 16]
    groups = [29, 23, 24]
    point_formats = [0]

    expected_string = "771,4866-4867-4865,0-23-65281-10-11-35-16,29-23-24,0"
    expected_hash = hashlib.md5(expected_string.encode("ascii")).hexdigest()

    assert compute_ja3(version, ciphers, extensions, groups, point_formats) == expected_hash


def test_compute_ja3_strips_grease_values_from_every_list():
    # 0x0a0a (2570) and 0x1a1a (6682) are GREASE values and must not appear in the string.
    version = 771
    ciphers = [2570, 4866, 4867]
    extensions = [6682, 0, 23]
    groups = [2570, 29]
    point_formats = [0]

    expected_string = "771,4866-4867,0-23,29,0"
    expected_hash = hashlib.md5(expected_string.encode("ascii")).hexdigest()

    assert compute_ja3(version, ciphers, extensions, groups, point_formats) == expected_hash


def test_compute_ja3_is_deterministic_for_same_input():
    args = (771, [4866, 4867], [0, 23], [29], [0])
    assert compute_ja3(*args) == compute_ja3(*args)
