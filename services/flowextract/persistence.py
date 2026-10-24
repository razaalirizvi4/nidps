"""Writes completed/partial flows to flow_record (this plan owns that table) and upserts the
minimal host row flow_record.host_id needs. Never writes host.risk_score (owned by the later Event
Store phase). Epoch -> ISO formatting here is NOT a new "current time" (utc_now_iso() remains the
only function that stamps *now*) -- it reformats an already-known packet-capture instant."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from common.schemas import FEATURE_COUNT, FlowFeatures, SCHEMA_VERSION, utc_now_iso
from services.flowextract.flow_assembler import EmittedFlow


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def upsert_host(conn, ip_address: str, mac_address: Optional[str] = None) -> int:
    now = utc_now_iso()
    conn.execute(
        """INSERT OR IGNORE INTO host (ip_address, mac_address, is_internal, first_seen, last_seen)
           VALUES (?, ?, 1, ?, ?)""",
        (ip_address, mac_address, now, now),
    )
    conn.execute("UPDATE host SET last_seen = ? WHERE ip_address = ?", (now, ip_address))
    conn.commit()
    row = conn.execute("SELECT host_id FROM host WHERE ip_address = ?", (ip_address,)).fetchone()
    return row[0]


def write_flow_record(
    conn, emitted: EmittedFlow, host_id: int, extractor_version: str = "1.0"
) -> int:
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=emitted.feature_values)
    if not features.validate():
        raise ValueError(
            f"feature vector failed validation: expected {FEATURE_COUNT} floats under schema "
            f"{SCHEMA_VERSION!r}, got {len(emitted.feature_values)} under {features.schema_version!r}"
        )
    cursor = conn.execute(
        """INSERT INTO flow_record
               (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
                segment_no, ja3, ja3s, sni, features, extractor_version)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            host_id, emitted.src_ip, emitted.dst_ip, emitted.src_port, emitted.dst_port,
            emitted.protocol, _epoch_to_iso(emitted.start_time), _epoch_to_iso(emitted.end_time),
            emitted.segment_no, emitted.tls.ja3, emitted.tls.ja3s, emitted.tls.server_name,
            json.dumps(emitted.feature_values), extractor_version,
        ),
    )
    conn.commit()
    return cursor.lastrowid
