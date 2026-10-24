"""JA3/JA3S TLS fingerprint computation, per Algorithm 5.1 (ch5.tex §5.3.3)."""

import hashlib

GREASE_VALUES = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in GREASE_VALUES]


def compute_ja3(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    groups: list[int],
    point_formats: list[int],
) -> str:
    """Computes the JA3 fingerprint of a TLS ClientHello.

    GREASE values are stripped from every list before joining, per Algorithm 5.1.
    Point formats are not GREASE-filtered (GREASE values never appear in that list
    in practice, but stripping is harmless if present).
    """
    fields = [
        str(version),
        "-".join(str(c) for c in _strip_grease(ciphers)),
        "-".join(str(e) for e in _strip_grease(extensions)),
        "-".join(str(g) for g in _strip_grease(groups)),
        "-".join(str(p) for p in _strip_grease(point_formats)),
    ]
    ja3_string = ",".join(fields)
    return hashlib.md5(ja3_string.encode("ascii")).hexdigest()
