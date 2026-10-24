import json

import pytest

from common.db.migrate import connect
from common.schemas import FEATURE_COUNT, TLSFingerprint
from services.flowextract.flow_assembler import EmittedFlow
from services.flowextract.persistence import upsert_host, write_flow_record


def _sample_emitted() -> EmittedFlow:
    return EmittedFlow(
        src_ip="10.0.0.5", dst_ip="93.184.216.34", src_port=51000, dst_port=443, protocol="TCP",
        start_time=1_700_000_000.0, end_time=1_700_000_000.5, segment_no=0, is_partial=False,
        feature_values=[0.0] * FEATURE_COUNT,
        tls=TLSFingerprint(ja3="abc", ja3s="def", server_name="example.com"),
    )


def test_upsert_host_is_idempotent_on_ip():
    conn = connect(":memory:")
    first = upsert_host(conn, "10.0.0.5")
    second = upsert_host(conn, "10.0.0.5")

    assert first == second
    count = conn.execute(
        "SELECT COUNT(*) FROM host WHERE ip_address = ?", ("10.0.0.5",)
    ).fetchone()[0]
    assert count == 1


def test_write_flow_record_persists_all_columns():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    emitted = _sample_emitted()

    flow_id = write_flow_record(conn, emitted, host_id, extractor_version="1.0")

    row = conn.execute(
        """SELECT host_id, src_ip, dst_ip, src_port, dst_port, protocol, segment_no, ja3, ja3s,
                  sni, features, extractor_version
           FROM flow_record WHERE flow_id = ?""",
        (flow_id,),
    ).fetchone()
    assert row == (
        host_id, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 0, "abc", "def",
        "example.com", json.dumps([0.0] * FEATURE_COUNT), "1.0",
    )


def test_write_flow_record_rejects_wrong_length_feature_vector():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    emitted = _sample_emitted()
    emitted.feature_values = [0.0] * 10

    with pytest.raises(ValueError):
        write_flow_record(conn, emitted, host_id)
