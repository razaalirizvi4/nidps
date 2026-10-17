# NIDPS Common Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `common/` package every other NIDPS service imports — shared value types, the
versioned event-bus message envelope, a Redis Streams client wrapper, the `Detector` interface, the
SQLite schema for all 12 data-dictionary tables, and a config system backed by that schema.

**Architecture:** A single importable Python package (`common/`) with no service-specific logic.
Every later phase (flow extraction, classification, decision/enforcement, watchdog, dashboard,
training) imports types and helpers from here instead of redefining them — that's what keeps six
independently-planned subsystems interoperable.

**Tech Stack:** Python 3.11+, `redis` (Redis Streams client) + `fakeredis` (tests), stdlib `sqlite3`,
stdlib `logging`/`json`/`dataclasses`/`enum`, `pytest`.

## Global Constraints

- Python 3.11+ for all code in this repo (spec Table: Technology Stack).
- No packet payloads or decrypted traffic are ever stored anywhere in this system (FR-11.2, NFR-14).
- All timestamps are UTC, ISO 8601 strings (spec Section 4.9 note). This plan's `utc_now_iso()` is
  the only function that should ever generate one — don't call `datetime.now()` directly elsewhere.
- The event bus is Redis Streams; the local database is SQLite 3 (spec Section 6, "proposed
  implementation" — this plan commits to the primary choice).
- The 12 tables are exactly: `admin_user`, `host`, `model_package`, `calibration_state`,
  `flow_record`, `evidence`, `verdict`, `block_entry`, `allowlist_entry`, `config_setting`,
  `component_event`, `audit_log` (spec Section 4.9, Tables 4.17-4.28). No other plan may add, rename,
  or change the columns of these tables without updating this one.
- Every tunable numeric threshold the spec leaves unstated or gives only as an "e.g." example is
  defined here as a `CONFIG_SETTING` row with a `min_value`/`max_value`, so the admin can change it
  at runtime (FR-10.3) instead of it being a hardcoded constant in some later service.
- XGBoost models are later saved as native JSON, not pickles, specifically to avoid deserialization
  code execution (spec Section 6.6.2) — this plan's `model_package.file_path` column just stores a
  path string; the format constraint applies to Phase 7 (training pipeline), not here.

---

## File Structure

```
nidps/
  common/
    __init__.py
    schemas.py          # enums + dataclasses: Layer, Action, HealthState, FailureMode,
                         #   EvidenceType, TLSFingerprint, FlowFeatures, Flow, Evidence,
                         #   Verdict, ComponentHealth, BlockEntry, utc_now_iso()
    bus_messages.py      # versioned JSON envelope: encode_envelope() / decode_envelope()
    bus.py               # EventBus: thin wrapper over redis-py Streams (publish/consume)
    detector.py          # Detector ABC: analyse() / heartbeat()
    config_schema.py     # CONFIG_KEYS: canonical list of every tunable setting + validate_value()
    config_loader.py     # seed_defaults() / get() / update() against the config_setting table
    logging_setup.py     # configure_logging(): one JSON log line format for every service
    db/
      __init__.py
      schema.sql         # DDL for all 12 tables
      migrate.py         # connect() / migrate(): idempotent schema application
  tests/
    unit/
      test_schemas.py
      test_bus_messages.py
      test_bus.py
      test_detector.py
      test_db_migrate.py
      test_config_loader.py
      test_logging_setup.py
  requirements.txt
  pytest.ini
  .gitignore
```

---

## Task 1: Project scaffolding and git init

**Files:**
- Create: `requirements.txt`
- Create: `pytest.ini`
- Create: `.gitignore`
- Create: `common/__init__.py`
- Create: `common/db/__init__.py`
- Create: `tests/unit/__init__.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: an installable, testable Python project that every later task in this plan (and every
  other phase's plan) assumes already exists.

- [ ] **Step 1: Initialize the git repository**

Run (from `D:\work\nidps`):
```bash
git init
```
Expected: `Initialized empty Git repository in D:/work/nidps/.git/`

- [ ] **Step 2: Create `.gitignore`**

```gitignore
__pycache__/
*.pyc
.pytest_cache/
*.sqlite3
.venv/
*.egg-info/
```

- [ ] **Step 3: Create `requirements.txt`**

```
redis>=5.0,<6.0
fakeredis>=2.20,<3.0
pytest>=7.4,<9.0
```

- [ ] **Step 4: Create `pytest.ini`**

```ini
[pytest]
pythonpath = .
testpaths = tests
```

- [ ] **Step 5: Create empty package markers**

`common/__init__.py`:
```python
```

`common/db/__init__.py`:
```python
```

`tests/unit/__init__.py`:
```python
```

- [ ] **Step 6: Install dependencies**

Run:
```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
```
Expected: packages install without error.

- [ ] **Step 7: Verify pytest runs with zero tests collected**

Run:
```bash
.venv/Scripts/pytest
```
Expected: exit code `5` ("no tests ran") — this confirms `pytest.ini` and the package layout are
wired up correctly before any real test exists.

- [ ] **Step 8: Commit**

```bash
git add requirements.txt pytest.ini .gitignore common/__init__.py common/db/__init__.py tests/unit/__init__.py
git commit -m "chore: scaffold NIDPS common package project structure"
```

---

## Task 2: Core shared types (`common/schemas.py`)

**Files:**
- Create: `common/schemas.py`
- Test: `tests/unit/test_schemas.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Layer`, `EvidenceType`, `Action`, `HealthState`, `FailureMode` (str enums);
  `TLSFingerprint`, `FlowFeatures`, `Flow`, `Evidence`, `Verdict`, `ComponentHealth`, `BlockEntry`
  (dataclasses); `utc_now_iso() -> str`; `SCHEMA_VERSION: str`; `FEATURE_COUNT: int`. Every later
  phase imports these types rather than defining its own.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_schemas.py
from common.schemas import FEATURE_COUNT, SCHEMA_VERSION, FlowFeatures, Layer


def test_flow_features_valid_when_length_and_version_match():
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)
    assert features.validate() is True


def test_flow_features_invalid_when_length_wrong():
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * 10)
    assert features.validate() is False


def test_flow_features_invalid_when_schema_version_wrong():
    features = FlowFeatures(schema_version="0.9", values=[0.0] * FEATURE_COUNT)
    assert features.validate() is False


def test_layer_values_match_db_check_constraint():
    assert {l.value for l in Layer} == {"L1", "ARP", "L2", "L3", "HOST"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_schemas.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.schemas'`

- [ ] **Step 3: Write `common/schemas.py`**

```python
"""Shared value types used across every NIDPS service. Fixed by this plan — import these
rather than redefining a Flow/Evidence/Verdict shape in a service's own code."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = "1.0"
FEATURE_COUNT = 78


class Layer(str, enum.Enum):
    L1_SIGNATURE = "L1"
    ARP = "ARP"
    L2_ANOMALY = "L2"
    L3_CLASSIFIER = "L3"
    HOST = "HOST"


class EvidenceType(str, enum.Enum):
    SIGNATURE = "SIGNATURE"
    ANOMALY = "ANOMALY"
    CLASS = "CLASS"
    EXFIL = "EXFIL"
    BEACON = "BEACON"


class Action(str, enum.Enum):
    PASS = "PASS"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


class HealthState(str, enum.Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


class FailureMode(str, enum.Enum):
    FAIL_OPEN = "FAIL_OPEN"
    FAIL_CLOSED = "FAIL_CLOSED"
    DEGRADED = "DEGRADED"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class TLSFingerprint:
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    server_name: Optional[str] = None


@dataclass
class FlowFeatures:
    schema_version: str
    values: list

    def validate(self) -> bool:
        return self.schema_version == SCHEMA_VERSION and len(self.values) == FEATURE_COUNT


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    end_time: str
    is_partial: bool
    features: FlowFeatures
    tls: Optional[TLSFingerprint] = None


@dataclass
class Evidence:
    source: Layer
    flow_id: Optional[str]
    host_ip: str
    kind: EvidenceType
    strength: float
    weight: float
    timestamp: str = field(default_factory=utc_now_iso)
    signature_id: Optional[int] = None
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    model_id: Optional[int] = None


@dataclass
class Verdict:
    action: Action
    layers: list
    explanation: str
    flow_id: Optional[str] = None
    host_ip: Optional[str] = None
    attack_class: Optional[str] = None
    timestamp: str = field(default_factory=utc_now_iso)


@dataclass
class ComponentHealth:
    name: str
    state: HealthState
    last_heartbeat: str
    queue_depth: int = 0
    cpu_pct: Optional[float] = None
    mem_mb: Optional[float] = None


@dataclass
class BlockEntry:
    ip: str
    reason: str
    duration_s: int
    offence_count: int
    created_at: str = field(default_factory=utc_now_iso)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_schemas.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add common/schemas.py tests/unit/test_schemas.py
git commit -m "feat: add shared NIDPS value types (common/schemas.py)"
```

---

## Task 3: Versioned event-bus message envelope (`common/bus_messages.py`)

**Files:**
- Create: `common/bus_messages.py`
- Test: `tests/unit/test_bus_messages.py`

**Interfaces:**
- Consumes: `common.schemas.{Evidence, Verdict, ComponentHealth, utc_now_iso}` (Task 2).
- Produces: `MessageType` enum (`EVIDENCE`, `VERDICT`, `HEARTBEAT`, `CONFIG_CHANGE`);
  `encode_envelope(message_type: MessageType, payload: Any) -> str`;
  `decode_envelope(raw: str) -> dict`. Later phases publish/consume only through these two
  functions — no service hand-rolls its own JSON shape.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_bus_messages.py
import pytest

from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer


def test_evidence_round_trip():
    ev = Evidence(
        source=Layer.L2_ANOMALY,
        flow_id="f1",
        host_ip="10.10.0.57",
        kind=EvidenceType.ANOMALY,
        strength=0.71,
        weight=2.0,
    )
    raw = encode_envelope(MessageType.EVIDENCE, ev)
    envelope = decode_envelope(raw)

    assert envelope["type"] == "evidence"
    assert envelope["payload"]["source"] == "L2"
    assert envelope["payload"]["strength"] == 0.71


def test_heartbeat_round_trip():
    health = ComponentHealth(
        name="flowextract", state=HealthState.NORMAL, last_heartbeat="2026-10-10T00:00:00Z"
    )
    raw = encode_envelope(MessageType.HEARTBEAT, health)
    envelope = decode_envelope(raw)

    assert envelope["payload"]["state"] == "NORMAL"


def test_decode_rejects_unknown_schema_version():
    raw = '{"schema_version": "9.9", "payload": {}}'
    with pytest.raises(ValueError):
        decode_envelope(raw)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_bus_messages.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.bus_messages'`

- [ ] **Step 3: Write `common/bus_messages.py`**

```python
"""Versioned JSON envelope wrapped around every event-bus message."""
from __future__ import annotations

import dataclasses
import enum
import json
import uuid
from typing import Any

from common.schemas import utc_now_iso

ENVELOPE_SCHEMA_VERSION = "1.0"


class MessageType(str, enum.Enum):
    EVIDENCE = "evidence"
    VERDICT = "verdict"
    HEARTBEAT = "heartbeat"
    CONFIG_CHANGE = "config_change"


def _default(obj: Any):
    if isinstance(obj, enum.Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    raise TypeError(f"Cannot serialize {type(obj)!r}")


def encode_envelope(message_type: MessageType, payload: Any) -> str:
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "message_id": str(uuid.uuid4()),
        "produced_at": utc_now_iso(),
        "type": message_type.value,
        "payload": payload,
    }
    return json.dumps(envelope, default=_default)


def decode_envelope(raw: str) -> dict:
    envelope = json.loads(raw)
    if envelope.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported envelope schema version: {envelope.get('schema_version')!r}"
        )
    return envelope
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_bus_messages.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add common/bus_messages.py tests/unit/test_bus_messages.py
git commit -m "feat: add versioned event-bus message envelope"
```

---

## Task 4: Redis Streams bus client (`common/bus.py`)

**Files:**
- Create: `common/bus.py`
- Test: `tests/unit/test_bus.py`

**Interfaces:**
- Consumes: `redis.Redis`-compatible client (real or `fakeredis`).
- Produces: `STREAM_EVIDENCE`, `STREAM_VERDICTS`, `STREAM_HEARTBEATS`, `STREAM_CONFIG_CHANGES`
  (stream name constants); `EventBus` class with `publish(stream: str, body: str) -> str`,
  `ensure_group(stream: str, group: str) -> None`,
  `consume(stream, group, consumer, handler: Callable[[str], None], count=10, block_ms=1000) -> None`.
  Every later phase publishes with `bus.publish(STREAM_EVIDENCE, encode_envelope(...))` and consumes
  with `bus.consume(...)` — no service calls `redis-py` directly.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_bus.py
import fakeredis

from common.bus import STREAM_EVIDENCE, EventBus


def test_publish_and_consume_round_trip():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_EVIDENCE, "hello")

    received = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=received.append, block_ms=100
    )

    assert received == ["hello"]


def test_consume_acks_so_message_is_not_redelivered():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_EVIDENCE, "once")

    first = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=first.append, block_ms=100
    )
    second = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=second.append, block_ms=100
    )

    assert first == ["once"]
    assert second == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_bus.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.bus'`

- [ ] **Step 3: Write `common/bus.py`**

```python
"""Thin wrapper over Redis Streams so services never touch the redis-py API directly."""
from __future__ import annotations

from typing import Callable

import redis

STREAM_EVIDENCE = "nidps:evidence"
STREAM_VERDICTS = "nidps:verdicts"
STREAM_HEARTBEATS = "nidps:heartbeats"
STREAM_CONFIG_CHANGES = "nidps:config_changes"


class EventBus:
    def __init__(self, client: "redis.Redis"):
        self._client = client

    @classmethod
    def from_url(cls, url: str = "redis://localhost:6379/0") -> "EventBus":
        return cls(redis.Redis.from_url(url, decode_responses=True))

    def publish(self, stream: str, body: str) -> str:
        return self._client.xadd(stream, {"body": body})

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            self._client.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        handler: Callable[[str], None],
        count: int = 10,
        block_ms: int = 1000,
    ) -> None:
        self.ensure_group(stream, group)
        response = self._client.xreadgroup(
            group, consumer, {stream: ">"}, count=count, block=block_ms
        )
        for _stream_name, entries in response or []:
            for entry_id, fields in entries:
                handler(fields["body"])
                self._client.xack(stream, group, entry_id)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_bus.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add common/bus.py tests/unit/test_bus.py
git commit -m "feat: add Redis Streams event-bus client wrapper"
```

---

## Task 5: `Detector` interface (`common/detector.py`)

**Files:**
- Create: `common/detector.py`
- Test: `tests/unit/test_detector.py`

**Interfaces:**
- Consumes: `common.schemas.{ComponentHealth, Evidence}` (Task 2).
- Produces: `Detector` abstract base class with `analyse(self, item: Any) -> Optional[list[Evidence]]`
  and `heartbeat(self) -> ComponentHealth`. Phase 2's `ArpMonitor`/`AnomalyDetector` and Phase 3's
  `AttackClassifier` all subclass this and implement nothing else — `DecisionEngine` (Phase 4) never
  needs to change when a new detector is added (NFR-18).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_detector.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/unit/test_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.detector'`

- [ ] **Step 3: Write `common/detector.py`**

```python
"""Common extension point for every detection layer (FR-2 through FR-5). A new detector
implements this interface and publishes Evidence; DecisionEngine never needs to change."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from common.schemas import ComponentHealth, Evidence


class Detector(ABC):
    name: str

    @abstractmethod
    def analyse(self, item: Any) -> Optional[list[Evidence]]:
        """Return zero or more Evidence objects for the given input, or None."""

    @abstractmethod
    def heartbeat(self) -> ComponentHealth:
        """Return this detector's current health for the watchdog."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/unit/test_detector.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add common/detector.py tests/unit/test_detector.py
git commit -m "feat: add Detector interface"
```

---

## Task 6: SQLite schema and migration runner (`common/db/`)

**Files:**
- Create: `common/db/schema.sql`
- Create: `common/db/migrate.py`
- Test: `tests/unit/test_db_migrate.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `connect(db_path: str) -> sqlite3.Connection` (opens the DB, enables foreign keys, applies
  the schema); `migrate(conn: sqlite3.Connection) -> None` (idempotent DDL application);
  `EXPECTED_TABLES: list[str]`. Every later phase that touches the database calls
  `common.db.migrate.connect(...)` instead of opening `sqlite3.connect()` directly, so the schema is
  always present.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_db_migrate.py
import sqlite3

from common.db.migrate import EXPECTED_TABLES, connect, migrate


def test_connect_creates_all_tables():
    conn = connect(":memory:")
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    names = {row[0] for row in rows}

    for table in EXPECTED_TABLES:
        assert table in names


def test_migrate_is_idempotent():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    migrate(conn)  # must not raise
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_db_migrate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.db.migrate'`

- [ ] **Step 3: Write `common/db/schema.sql`**

```sql
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
CREATE INDEX IF NOT EXISTS idx_host_ip ON host (ip_address);

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
    state            TEXT NOT NULL CHECK (state IN ('RUNNING', 'DEGRADED', 'FAILED', 'RECOVERING')),
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
```

- [ ] **Step 4: Write `common/db/migrate.py`**

```python
"""Applies common/db/schema.sql to a SQLite database. Idempotent -- safe to call on every
service start (FR-11.1)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

EXPECTED_TABLES = [
    "admin_user", "host", "model_package", "calibration_state", "flow_record",
    "evidence", "verdict", "block_entry", "allowlist_entry", "config_setting",
    "component_event", "audit_log",
]


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_db_migrate.py -v`
Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add common/db/schema.sql common/db/migrate.py tests/unit/test_db_migrate.py
git commit -m "feat: add SQLite schema for all 12 NIDPS tables and migration runner"
```

---

## Task 7: Canonical config key list (`common/config_schema.py`)

**Files:**
- Create: `common/config_schema.py`
- Test: `tests/unit/test_config_schema.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ConfigKey` dataclass (`key`, `value_type`, `default`, `min_value`, `max_value`);
  `CONFIG_KEYS: list[ConfigKey]`; `CONFIG_KEYS_BY_NAME: dict[str, ConfigKey]`;
  `validate_value(key: str, value) -> None` (raises `ValueError` on an invalid value,
  `KeyError` on an unknown key). Task 8's config loader and every later phase's settings UI/API read
  from `CONFIG_KEYS` rather than inventing their own list of tunables.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_config_schema.py
import pytest

from common.config_schema import CONFIG_KEYS_BY_NAME, validate_value


def test_every_key_has_a_default_within_its_own_range():
    for spec in CONFIG_KEYS_BY_NAME.values():
        if spec.min_value is not None:
            assert spec.default >= spec.min_value
        if spec.max_value is not None:
            assert spec.default <= spec.max_value


def test_validate_value_accepts_in_range_value():
    validate_value("risk.block_threshold", 7.0)  # must not raise


def test_validate_value_rejects_out_of_range_value():
    with pytest.raises(ValueError):
        validate_value("risk.block_threshold", 999.0)


def test_validate_value_rejects_wrong_type():
    with pytest.raises(ValueError):
        validate_value("detection.layer1_enabled", "yes")


def test_validate_value_rejects_unknown_key():
    with pytest.raises(KeyError):
        validate_value("no.such.key", 1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_config_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.config_schema'`

- [ ] **Step 3: Write `common/config_schema.py`**

```python
"""Canonical list of every tunable NIDPS setting (FR-10.3), backed by the config_setting table.
The spec leaves most of these numeric values unstated or gives them only as "e.g." examples
(see docs/superpowers/plans/2026-10-10-00-master-roadmap.md for the rationale behind each
default chosen here). Two defaults ARE implied by the spec itself: risk.block_threshold=6.0 and
enforcement.rate_limit_per_minute=10 both match numbers shown in the dashboard mockups
(Figures 4.5 and 4.6)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

Number = Union[int, float]


@dataclass(frozen=True)
class ConfigKey:
    key: str
    value_type: type
    default: Union[Number, str, bool]
    min_value: Optional[Number] = None
    max_value: Optional[Number] = None


CONFIG_KEYS: list[ConfigKey] = [
    ConfigKey("network.active_timeout_s", int, 10, 5, 30),
    ConfigKey("network.idle_timeout_s", int, 30, 10, 120),
    ConfigKey("detection.layer1_enabled", bool, True),
    ConfigKey("detection.layer2_enabled", bool, True),
    ConfigKey("detection.layer3_enabled", bool, True),
    ConfigKey("anomaly.n_estimators", int, 100, 50, 500),
    ConfigKey("anomaly.subsample_size", int, 256, 64, 1024),
    ConfigKey("anomaly.calibration_window_hours", int, 48, 24, 72),
    ConfigKey("anomaly.calibration_percentile", float, 99.5, 90.0, 99.99),
    ConfigKey("anomaly.calibration_min_samples", int, 2000, 100, 100000),
    ConfigKey("anomaly.calibration_max_shift", float, 0.15, 0.0, 0.5),
    ConfigKey("anomaly.recalibration_interval_days", int, 7, 1, 30),
    ConfigKey("exfil.ewma_alpha", float, 0.3, 0.01, 1.0),
    ConfigKey("exfil.bucket_seconds", int, 60, 10, 300),
    ConfigKey("exfil.k_std", float, 4.0, 1.0, 10.0),
    ConfigKey("exfil.u_max_percentile", float, 99.9, 90.0, 99.99),
    ConfigKey("beacon.min_connections", int, 5, 2, 50),
    ConfigKey("beacon.cv_threshold", float, 0.15, 0.01, 1.0),
    ConfigKey("fusion.theta_block", float, 0.90, 0.5, 1.0),
    ConfigKey("fusion.theta_alert", float, 0.70, 0.3, 1.0),
    ConfigKey("fusion.theta_c", float, 0.50, 0.1, 1.0),
    ConfigKey("risk.half_life_s", int, 600, 60, 3600),
    ConfigKey("risk.block_threshold", float, 6.0, 1.0, 20.0),
    ConfigKey("risk.weight_signature", float, 3.0, 0.0, 10.0),
    ConfigKey("risk.weight_anomaly", float, 2.0, 0.0, 10.0),
    ConfigKey("risk.weight_class", float, 2.5, 0.0, 10.0),
    ConfigKey("risk.weight_exfil", float, 2.0, 0.0, 10.0),
    ConfigKey("risk.weight_beacon", float, 2.5, 0.0, 10.0),
    ConfigKey("enforcement.base_block_s", int, 300, 30, 3600),
    ConfigKey("enforcement.max_block_s", int, 86400, 3600, 604800),
    ConfigKey("enforcement.rate_limit_per_minute", int, 10, 1, 1000),
    ConfigKey("watchdog.heartbeat_interval_s", float, 1.0, 0.1, 10.0),
    ConfigKey("watchdog.missed_heartbeats_threshold", int, 3, 1, 10),
    ConfigKey("watchdog.cpu_high_watermark", float, 0.85, 0.5, 1.0),
    ConfigKey("watchdog.cpu_low_watermark", float, 0.60, 0.1, 0.95),
    ConfigKey("retention.flow_days", int, 7, 1, 90),
    ConfigKey("auth.lockout_attempts", int, 5, 3, 10),
    ConfigKey("auth.lockout_duration_s", int, 300, 60, 3600),
    ConfigKey("rules.update_interval_hours", int, 24, 1, 168),
    ConfigKey("failure_mode", str, "FAIL_OPEN"),
]

CONFIG_KEYS_BY_NAME: dict[str, ConfigKey] = {k.key: k for k in CONFIG_KEYS}


def validate_value(key: str, value) -> None:
    spec = CONFIG_KEYS_BY_NAME[key]
    if spec.value_type is bool:
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a bool")
        return
    if spec.value_type in (int, float):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError(f"{key} must be numeric")
        if spec.min_value is not None and value < spec.min_value:
            raise ValueError(f"{key}={value} below min {spec.min_value}")
        if spec.max_value is not None and value > spec.max_value:
            raise ValueError(f"{key}={value} above max {spec.max_value}")
        return
    if spec.value_type is str:
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        return
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_config_schema.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add common/config_schema.py tests/unit/test_config_schema.py
git commit -m "feat: add canonical NIDPS config key list and validator"
```

---

## Task 8: Database-backed config loader (`common/config_loader.py`)

**Files:**
- Create: `common/config_loader.py`
- Test: `tests/unit/test_config_loader.py`

**Interfaces:**
- Consumes: `common.config_schema.{CONFIG_KEYS, CONFIG_KEYS_BY_NAME, validate_value}` (Task 7),
  `common.schemas.utc_now_iso` (Task 2), `common.db.migrate.connect` (Task 6).
- Produces: `seed_defaults(conn) -> None`; `get(conn, key: str) -> int | float | str | bool`;
  `update(conn, key: str, value, user_id: int | None = None) -> None` (validates, writes the new
  value, and appends an `audit_log` row — FR-10.6). Phase 6's dashboard config API calls these
  directly; no other phase re-implements config persistence.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_config_loader.py
import pytest

from common.config_loader import get, seed_defaults, update
from common.db.migrate import connect


def test_seed_defaults_populates_every_key():
    conn = connect(":memory:")
    seed_defaults(conn)

    count = conn.execute("SELECT COUNT(*) FROM config_setting").fetchone()[0]
    assert count > 0
    assert get(conn, "risk.block_threshold") == 6.0


def test_update_rejects_out_of_range_value():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(ValueError):
        update(conn, "risk.block_threshold", 999.0)

    assert get(conn, "risk.block_threshold") == 6.0


def test_update_writes_audit_log():
    conn = connect(":memory:")
    seed_defaults(conn)

    update(conn, "risk.block_threshold", 7.5, user_id=None)

    row = conn.execute(
        "SELECT action, new_value FROM audit_log WHERE target = 'risk.block_threshold'"
    ).fetchone()
    assert row == ("CONFIG_CHANGE", "7.5")
    assert get(conn, "risk.block_threshold") == 7.5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_config_loader.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.config_loader'`

- [ ] **Step 3: Write `common/config_loader.py`**

```python
"""Loads defaults into config_setting on first run and provides typed get/update access
backed by the database (FR-10.3, FR-10.6)."""
from __future__ import annotations

import sqlite3
from typing import Union

from common.config_schema import CONFIG_KEYS, CONFIG_KEYS_BY_NAME, validate_value
from common.schemas import utc_now_iso

Number = Union[int, float]


def seed_defaults(conn: sqlite3.Connection) -> None:
    for spec in CONFIG_KEYS:
        conn.execute(
            """INSERT OR IGNORE INTO config_setting
               (setting_key, value, default_value, min_value, max_value)
               VALUES (?, ?, ?, ?, ?)""",
            (
                spec.key,
                str(spec.default),
                str(spec.default),
                str(spec.min_value) if spec.min_value is not None else None,
                str(spec.max_value) if spec.max_value is not None else None,
            ),
        )
    conn.commit()


def _cast(key: str, raw: str):
    spec = CONFIG_KEYS_BY_NAME[key]
    if spec.value_type is bool:
        return raw in ("True", "true", "1")
    return spec.value_type(raw)


def get(conn: sqlite3.Connection, key: str) -> Union[Number, str, bool]:
    row = conn.execute(
        "SELECT value FROM config_setting WHERE setting_key = ?", (key,)
    ).fetchone()
    if row is None:
        raise KeyError(key)
    return _cast(key, row[0])


def update(conn: sqlite3.Connection, key: str, value, user_id: int | None = None) -> None:
    validate_value(key, value)
    old = conn.execute(
        "SELECT value FROM config_setting WHERE setting_key = ?", (key,)
    ).fetchone()
    conn.execute(
        "UPDATE config_setting SET value = ?, updated_by = ?, updated_at = ? WHERE setting_key = ?",
        (str(value), user_id, utc_now_iso(), key),
    )
    conn.execute(
        """INSERT INTO audit_log (user_id, action, target, old_value, new_value, timestamp)
           VALUES (?, 'CONFIG_CHANGE', ?, ?, ?, ?)""",
        (user_id, key, old[0] if old else None, str(value), utc_now_iso()),
    )
    conn.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_config_loader.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add common/config_loader.py tests/unit/test_config_loader.py
git commit -m "feat: add database-backed config loader with audit logging"
```

---

## Task 9: Structured JSON logging (`common/logging_setup.py`)

**Files:**
- Create: `common/logging_setup.py`
- Test: `tests/unit/test_logging_setup.py`

**Interfaces:**
- Consumes: stdlib `logging`.
- Produces: `configure_logging(component: str, level: int = logging.INFO) -> logging.Logger`. Every
  service's entry point calls this once at startup so systemd/journald output is uniformly
  parseable JSON across all six services plus the training pipeline.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_logging_setup.py
import json
import logging

from common.logging_setup import configure_logging


def test_log_line_is_valid_json_with_expected_fields(capsys):
    logger = configure_logging("test-component", level=logging.INFO)
    logger.info("hello world")

    captured = capsys.readouterr()
    line = captured.out.strip().splitlines()[-1]
    payload = json.loads(line)

    assert payload["level"] == "INFO"
    assert payload["component"] == "test-component"
    assert payload["message"] == "hello world"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/unit/test_logging_setup.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'common.logging_setup'`

- [ ] **Step 3: Write `common/logging_setup.py`**

```python
"""One structured JSON log format shared by every NIDPS service, so journald/systemd output
is consistently parseable."""
from __future__ import annotations

import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(component: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(component)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/unit/test_logging_setup.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add common/logging_setup.py tests/unit/test_logging_setup.py
git commit -m "feat: add structured JSON logging for all NIDPS services"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:** FR-10.3/10.6 → Tasks 7-8; FR-11.1 (local DB for all event types) → Task 6;
  FR-11.2 (no packet contents stored) → enforced structurally (no `payload`/`raw_packet` column
  exists anywhere in `schema.sql`); NFR-18 (new detector without touching other components) →
  Task 5's `Detector` ABC; "versioned JSON schema" (Section 6.6.4) → Task 3's `schema_version` field.
- **Placeholder scan:** none found — every step has complete code and literal expected output.
- **Type consistency:** `Evidence.source` is typed `Layer` everywhere it's used (Task 2, Task 3's
  test); `ComponentHealth.state` is `HealthState` everywhere; `config_loader.get()`/`update()` key
  strings match `config_schema.CONFIG_KEYS` exactly (both modules import the same list — no
  duplicated key names to drift apart).
