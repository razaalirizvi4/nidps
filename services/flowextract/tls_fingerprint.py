"""Algorithm 5.2: JA3/JA3S fingerprinting, isolated behind compute_tls_fingerprint() so a future
JA4 migration (the spec flags modern browsers' TLS extension randomization as degrading JA3's
stability) touches only this file."""
from __future__ import annotations

import hashlib
import struct
from typing import Optional

GREASE_VALUES = frozenset(
    {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }
)

_EXT_SUPPORTED_GROUPS = 0x000a
_EXT_EC_POINT_FORMATS = 0x000b
_EXT_SERVER_NAME = 0x0000


def _remove_grease(values: list) -> list:
    return [v for v in values if v not in GREASE_VALUES]


def parse_client_hello_body(body: bytes) -> dict:
    try:
        offset = 0
        version = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        offset += 32  # random
        session_id_len = body[offset]
        offset += 1 + session_id_len
        cipher_len = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        cipher_suites = [
            struct.unpack_from("!H", body, offset + i)[0] for i in range(0, cipher_len, 2)
        ]
        offset += cipher_len
        comp_len = body[offset]
        offset += 1 + comp_len

        groups: list = []
        point_formats: list = []
        extensions: list = []
        server_name: Optional[str] = None

        if offset < len(body):
            ext_total_len = struct.unpack_from("!H", body, offset)[0]
            offset += 2
            end = offset + ext_total_len
            while offset < end:
                ext_type, ext_len = struct.unpack_from("!HH", body, offset)
                offset += 4
                ext_data = body[offset : offset + ext_len]
                offset += ext_len
                extensions.append(ext_type)
                if ext_type == _EXT_SUPPORTED_GROUPS:
                    glen = struct.unpack_from("!H", ext_data, 0)[0]
                    groups = [
                        struct.unpack_from("!H", ext_data, 2 + i)[0] for i in range(0, glen, 2)
                    ]
                elif ext_type == _EXT_EC_POINT_FORMATS:
                    plen = ext_data[0]
                    point_formats = list(ext_data[1 : 1 + plen])
                elif ext_type == _EXT_SERVER_NAME:
                    if len(ext_data) >= 5:
                        name_len = struct.unpack_from("!H", ext_data, 3)[0]
                        server_name = ext_data[5 : 5 + name_len].decode("ascii", errors="replace")

        return {
            "version": version,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "groups": groups,
            "point_formats": point_formats,
            "server_name": server_name,
        }
    except (struct.error, IndexError, ValueError):
        return {
            "version": 0,
            "cipher_suites": [],
            "extensions": [],
            "groups": [],
            "point_formats": [],
            "server_name": None,
        }


def parse_server_hello_body(body: bytes) -> dict:
    try:
        offset = 0
        version = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        offset += 32  # random
        session_id_len = body[offset]
        offset += 1 + session_id_len
        cipher_suite = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        offset += 1  # compression method

        extensions: list = []
        if offset < len(body):
            ext_total_len = struct.unpack_from("!H", body, offset)[0]
            offset += 2
            end = offset + ext_total_len
            while offset < end:
                ext_type, ext_len = struct.unpack_from("!HH", body, offset)
                offset += 4 + ext_len
                extensions.append(ext_type)

        return {"version": version, "cipher_suites": [cipher_suite], "extensions": extensions}
    except (struct.error, IndexError, ValueError):
        return {"version": 0, "cipher_suites": [], "extensions": []}


def compute_tls_fingerprint(
    version: int,
    cipher_suites: list,
    extensions: list,
    groups: Optional[list] = None,
    point_formats: Optional[list] = None,
) -> str:
    ciphers = _remove_grease(cipher_suites)
    exts = _remove_grease(extensions)
    if groups is None and point_formats is None:
        # ServerHello: s_JA3S = Version,Cipher,Extensions -- exactly 3 fields, no trailing commas.
        s = "{},{},{}".format(
            version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
        )
    else:
        # ClientHello: s_JA3 = Version,Ciphers,Extensions,Groups,PointFormats -- 5 fields. An empty
        # list (as opposed to None) still contributes its field as an empty string between commas.
        grps = _remove_grease(groups or [])
        pfs = _remove_grease(point_formats or [])
        s = "{},{},{},{},{}".format(
            version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
            "-".join(str(g) for g in grps),
            "-".join(str(p) for p in pfs),
        )
    return hashlib.md5(s.encode("ascii")).hexdigest()
