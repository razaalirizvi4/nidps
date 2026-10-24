-- NIDPS database schema (spec Section 4.9, Tables 4.17-4.28). All timestamps are UTC ISO 8601
-- text. This is the single source of truth for the 12 data-dictionary tables -- no other plan
-- may redefine these columns.

CREATE TABLE IF NOT EXISTS admin_user (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_login      TEXT
);

CREATE TABLE IF NOT EXISTS host (
    host_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    mac_address TEXT,
    hostname    TEXT,
    is_internal INTEGER NOT NULL CHECK (is_internal IN (0, 1)),
    risk_score  REAL NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_ip ON host (ip_address);

CREATE TABLE IF NOT EXISTS model_package (
    model_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    model_type        TEXT NOT NULL CHECK (model_type IN ('IFOREST', 'RF', 'XGB')),
    version           TEXT NOT NULL,
    file_path         TEXT NOT NULL,
    feature_list_hash TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    class_list        TEXT,
    training_data     TEXT,
    metrics           TEXT,
    is_active         INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    deployed_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_type_version ON model_package (model_type, version);

CREATE TABLE IF NOT EXISTS calibration_state (
    calib_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id     INTEGER NOT NULL REFERENCES model_package (model_id),
    tau          REAL NOT NULL,
    tau_global   REAL NOT NULL,
    percentile   REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    u_max        INTEGER,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS flow_record (
    flow_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id           INTEGER NOT NULL REFERENCES host (host_id),
    src_ip            TEXT NOT NULL,
    dst_ip            TEXT NOT NULL,
    src_port          INTEGER NOT NULL,
    dst_port          INTEGER NOT NULL,
    protocol          TEXT NOT NULL,
    start_time        TEXT NOT NULL,
    end_time          TEXT NOT NULL,
    segment_no        INTEGER NOT NULL DEFAULT 0,
    ja3               TEXT,
    ja3s              TEXT,
    sni               TEXT,
    features          TEXT NOT NULL,
    extractor_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flow_host ON flow_record (host_id);
CREATE INDEX IF NOT EXISTS idx_flow_start ON flow_record (start_time);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         INTEGER REFERENCES flow_record (flow_id),
    host_id         INTEGER NOT NULL REFERENCES host (host_id),
    layer           TEXT NOT NULL CHECK (layer IN ('L1', 'ARP', 'L2', 'L3', 'HOST')),
    evidence_type   TEXT NOT NULL
        CHECK (evidence_type IN ('SIGNATURE', 'ANOMALY', 'CLASS', 'EXFIL', 'BEACON')),
    signature_id    INTEGER,
    score           REAL,
    predicted_class TEXT,
    confidence      REAL,
    weight          REAL NOT NULL,
    model_id        INTEGER REFERENCES model_package (model_id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_flow ON evidence (flow_id);
CREATE INDEX IF NOT EXISTS idx_evidence_host ON evidence (host_id);

CREATE TABLE IF NOT EXISTS verdict (
    verdict_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id      INTEGER REFERENCES flow_record (flow_id),
    host_id      INTEGER NOT NULL REFERENCES host (host_id),
    decision     TEXT NOT NULL CHECK (decision IN ('PASS', 'ALERT', 'BLOCK')),
    layers       TEXT NOT NULL,
    attack_class TEXT,
    explanation  TEXT NOT NULL,
    reviewed     INTEGER NOT NULL DEFAULT 0 CHECK (reviewed IN (0, 1)),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_verdict_host ON verdict (host_id);

CREATE TABLE IF NOT EXISTS block_entry (
    block_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES host (host_id),
    verdict_id    INTEGER NOT NULL REFERENCES verdict (verdict_id),
    offence_count INTEGER NOT NULL,
    duration_s    INTEGER NOT NULL,
    start_time    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'SUPPRESSED')),
    released_by   INTEGER REFERENCES admin_user (user_id),
    released_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_block_host ON block_entry (host_id);
CREATE INDEX IF NOT EXISTS idx_block_status ON block_entry (status);

CREATE TABLE IF NOT EXISTS allowlist_entry (
    entry_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    address      TEXT NOT NULL UNIQUE,
    description  TEXT,
    is_permanent INTEGER NOT NULL DEFAULT 0 CHECK (is_permanent IN (0, 1)),
    added_by     INTEGER REFERENCES admin_user (user_id),
    added_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS config_setting (
    setting_key   TEXT PRIMARY KEY,
    value         TEXT NOT NULL,
    default_value TEXT NOT NULL,
    min_value     TEXT,
    max_value     TEXT,
    updated_by    INTEGER REFERENCES admin_user (user_id),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS component_event (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    component        TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('NORMAL', 'DEGRADED', 'FAILED', 'RECOVERING')),
    failure_mode     TEXT,
    detected_at      TEXT,
    recovered_at     TEXT,
    packets_dropped  INTEGER NOT NULL DEFAULT 0,
    packets_bypassed INTEGER NOT NULL DEFAULT 0,
    details          TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER REFERENCES admin_user (user_id),
    action    TEXT NOT NULL,
    target    TEXT,
    old_value TEXT,
    new_value TEXT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

PRAGMA user_version = 1;
