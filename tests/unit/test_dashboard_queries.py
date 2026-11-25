from common.db.migrate import connect
from services.dashboard import queries


def _seed_host_verdict_evidence(conn):
    conn.execute("INSERT INTO host (ip_address, is_internal, hostname) VALUES ('10.0.0.5', 1, 'office-laptop')")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, attack_class, explanation, created_at) "
        "VALUES (?, 'BLOCK', '[\"L1\",\"L3\"]', 'BRUTE_FORCE', 'signature + model agree', '2026-01-01T00:00:00Z')",
        (host_id,),
    )
    verdict_id = conn.execute("SELECT verdict_id FROM verdict").fetchone()[0]
    conn.execute(
        "INSERT INTO evidence (host_id, layer, evidence_type, signature_id, score, weight, created_at) "
        "VALUES (?, 'L1', 'SIGNATURE', 2032754, 1.0, 3.0, '2026-01-01T00:00:00Z')",
        (host_id,),
    )
    conn.commit()
    return host_id, verdict_id


def test_list_alerts_returns_recent_verdicts_with_host_ip():
    conn = connect(":memory:")
    _seed_host_verdict_evidence(conn)

    alerts = queries.list_alerts(conn)

    assert len(alerts) == 1
    assert alerts[0]["host_ip"] == "10.0.0.5"
    assert alerts[0]["decision"] == "BLOCK"
    assert alerts[0]["attack_class"] == "BRUTE_FORCE"


def test_list_alerts_filters_by_host_ip():
    conn = connect(":memory:")
    _seed_host_verdict_evidence(conn)

    assert len(queries.list_alerts(conn, host_ip="10.0.0.5")) == 1
    assert len(queries.list_alerts(conn, host_ip="10.0.0.99")) == 0


def test_alert_evidence_returns_evidence_for_that_hosts_flows():
    conn = connect(":memory:")
    host_id, verdict_id = _seed_host_verdict_evidence(conn)

    evidence = queries.alert_evidence(conn, verdict_id)

    assert len(evidence) == 1
    assert evidence[0]["layer"] == "L1"
    assert evidence[0]["signature_id"] == 2032754


def test_list_blocked_hosts_returns_active_blocks_only():
    conn = connect(":memory:")
    host_id, verdict_id = _seed_host_verdict_evidence(conn)
    conn.execute(
        "INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time, "
        "expires_at, status) VALUES (?, ?, 1, 300, '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'ACTIVE')",
        (host_id, verdict_id),
    )
    conn.commit()

    blocked = queries.list_blocked_hosts(conn)

    assert len(blocked) == 1
    assert blocked[0]["ip_address"] == "10.0.0.5"


def test_allowlist_add_list_remove_round_trip():
    conn = connect(":memory:")

    entry_id = queries.add_allowlist_entry(conn, "192.168.1.1", "ISP gateway", added_by=None)
    assert len(queries.list_allowlist(conn)) == 1

    queries.remove_allowlist_entry(conn, entry_id)
    assert len(queries.list_allowlist(conn)) == 0


def test_list_hosts_returns_risk_scores():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal, risk_score) VALUES ('10.0.0.5', 1, 6.4)")
    conn.commit()

    hosts = queries.list_hosts(conn)

    assert hosts[0]["risk_score"] == 6.4


def test_component_health_reads_from_component_event():
    conn = connect(":memory:")
    conn.execute(
        "INSERT INTO component_event (component, state, detected_at, recovered_at) "
        "VALUES ('enforcer', 'NORMAL', NULL, NULL)"
    )
    conn.commit()

    health = queries.component_health(conn)

    assert health[0]["component"] == "enforcer"


def test_component_health_is_empty_when_nothing_has_published_yet():
    conn = connect(":memory:")

    assert queries.component_health(conn) == []


def test_list_models_returns_model_package_rows():
    conn = connect(":memory:")
    conn.execute(
        "INSERT INTO model_package (model_type, version, file_path, feature_list_hash, "
        "extractor_version, is_active) VALUES ('RF', '1.0.0', '/models/rf.joblib', 'abc', '1.0', 1)"
    )
    conn.commit()

    models = queries.list_models(conn)

    assert models[0]["model_type"] == "RF"
    assert models[0]["is_active"] is True
