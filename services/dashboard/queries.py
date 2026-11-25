"""Read-only query helpers backing the Alerts, Blocked Hosts & Allowlist, Overview device list,
System Health, and Settings/Models screens (FR-9.3-9.7, FR-10.4). Reads model_package directly
with raw SQL rather than importing models.registry.ModelRegistry, matching the existing codebase's
convention (e.g. services/decision/allowlist.py reads allowlist_entry with raw SQL rather than
pulling in another service's module) of not reaching across service boundaries for a read.

component_health() and list_models() can legitimately return an empty list: nothing in this
codebase yet writes component_event (no watchdog service exists) or inserts model_package rows for
a trained model (anomaly_service logs a warning and runs with host-behaviour checks only until one
is loaded) -- those screens will reflect that honestly rather than show fabricated rows."""
from __future__ import annotations

import json
import sqlite3


def list_alerts(
    conn: sqlite3.Connection, limit: int = 50, host_ip: str | None = None,
    attack_class: str | None = None,
) -> list[dict]:
    sql = (
        "SELECT verdict.verdict_id, verdict.flow_id, host.ip_address, verdict.decision, "
        "verdict.layers, verdict.attack_class, verdict.explanation, verdict.created_at "
        "FROM verdict JOIN host ON host.host_id = verdict.host_id WHERE 1=1"
    )
    params: list = []
    if host_ip is not None:
        sql += " AND host.ip_address = ?"
        params.append(host_ip)
    if attack_class is not None:
        sql += " AND verdict.attack_class = ?"
        params.append(attack_class)
    sql += " ORDER BY verdict.created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "verdict_id": r[0], "flow_id": r[1], "host_ip": r[2], "decision": r[3],
            "layers": json.loads(r[4]), "attack_class": r[5], "explanation": r[6],
            "created_at": r[7],
        }
        for r in rows
    ]


def alert_evidence(conn: sqlite3.Connection, verdict_id: int) -> list[dict]:
    rows = conn.execute(
        """SELECT evidence.layer, evidence.evidence_type, evidence.signature_id, evidence.score,
                  evidence.predicted_class, evidence.confidence, evidence.weight, evidence.created_at
           FROM evidence
           JOIN verdict ON verdict.flow_id = evidence.flow_id OR verdict.host_id = evidence.host_id
           WHERE verdict.verdict_id = ?
           ORDER BY evidence.created_at""",
        (verdict_id,),
    ).fetchall()
    return [
        {
            "layer": r[0], "evidence_type": r[1], "signature_id": r[2], "score": r[3],
            "predicted_class": r[4], "confidence": r[5], "weight": r[6], "created_at": r[7],
        }
        for r in rows
    ]


def list_blocked_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT host.ip_address, host.hostname, verdict.attack_class, verdict.layers,
                  block_entry.start_time, block_entry.expires_at, block_entry.block_id
           FROM block_entry
           JOIN host ON host.host_id = block_entry.host_id
           JOIN verdict ON verdict.verdict_id = block_entry.verdict_id
           WHERE block_entry.status = 'ACTIVE'
           ORDER BY block_entry.start_time DESC"""
    ).fetchall()
    return [
        {
            "ip_address": r[0], "hostname": r[1], "attack_class": r[2], "layers": json.loads(r[3]),
            "start_time": r[4], "expires_at": r[5], "block_id": r[6],
        }
        for r in rows
    ]


def list_allowlist(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT entry_id, address, description, is_permanent, added_by, added_at "
        "FROM allowlist_entry ORDER BY added_at"
    ).fetchall()
    return [
        {
            "entry_id": r[0], "address": r[1], "description": r[2],
            "is_permanent": bool(r[3]), "added_by": r[4], "added_at": r[5],
        }
        for r in rows
    ]


def add_allowlist_entry(
    conn: sqlite3.Connection, address: str, description: str, added_by: int | None,
) -> int:
    from common.schemas import utc_now_iso

    cursor = conn.execute(
        "INSERT INTO allowlist_entry (address, description, added_by, added_at) VALUES (?, ?, ?, ?)",
        (address, description, added_by, utc_now_iso()),
    )
    conn.commit()
    return cursor.lastrowid


def remove_allowlist_entry(conn: sqlite3.Connection, entry_id: int) -> None:
    conn.execute("DELETE FROM allowlist_entry WHERE entry_id = ?", (entry_id,))
    conn.commit()


def list_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT ip_address, mac_address, hostname, risk_score, first_seen, last_seen FROM host "
        "ORDER BY risk_score DESC"
    ).fetchall()
    return [
        {
            "ip_address": r[0], "mac_address": r[1], "hostname": r[2], "risk_score": r[3],
            "first_seen": r[4], "last_seen": r[5],
        }
        for r in rows
    ]


def component_health(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT component, state, detected_at, recovered_at, packets_dropped, packets_bypassed "
        "FROM component_event ORDER BY event_id DESC"
    ).fetchall()
    return [
        {
            "component": r[0], "state": r[1], "detected_at": r[2], "recovered_at": r[3],
            "packets_dropped": r[4], "packets_bypassed": r[5],
        }
        for r in rows
    ]


def list_models(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT model_type, version, is_active, metrics, deployed_at FROM model_package "
        "ORDER BY model_type, deployed_at DESC"
    ).fetchall()
    return [
        {
            "model_type": r[0], "version": r[1], "is_active": bool(r[2]),
            "metrics": json.loads(r[3]) if r[3] else None, "deployed_at": r[4],
        }
        for r in rows
    ]
