# NIDPS Management Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `services/dashboard/` — the one graphical interface in the system (spec Section 4.8):
a FastAPI web API plus the Event Store that turns bus traffic into persisted `evidence`/`verdict`
rows, session-authenticated access for the Network Administrator, live counters pushed over
WebSocket, and the six screens the spec's GUI section defines (Login, Overview, Intrusion Alerts,
Blocked Hosts & Allowlist, Configuration, System Health).

**Architecture:** A single long-running `services/dashboard/main.py` process that does three things
concurrently: (1) runs the Event Store — a background consumer thread that subscribes to
`STREAM_EVIDENCE`, `STREAM_VERDICTS` and `STREAM_HOST_SCORES` under its own consumer group and
persists `evidence`/`verdict` rows and `host.risk_score` updates, the one database-writing role the
master roadmap and Phase 4 both call out as "the (separate, later) Event Store"; (2) maintains
in-memory live counters by consuming `STREAM_FLOWS`/`STREAM_VERDICTS` under a second, independent
consumer group, per the spec's explicit design note that "live counters shown on the dashboard are
kept in memory and on the event bus rather than in the database" (spec Section 4.9); (3) serves a
FastAPI app (session-cookie auth, REST endpoints per screen, a WebSocket push channel for FR-9.2's
2-second refresh) via `uvicorn`. All three share one SQLite connection and one `EventBus` instance,
wired together in `main.py`.

**Tech Stack:** Python 3.11+, `fastapi`+`uvicorn[standard]` (added by this plan; the spec's own
Technology Stack table names "FastAPI (or Flask) with WebSocket support"), `redis`/`fakeredis`
(already present), stdlib `sqlite3`/`hashlib`/`hmac`/`secrets`/`csv`/`threading`, `pytest`,
`httpx` (added by this plan, required by FastAPI's `TestClient`).

## Global Constraints

- Python 3.11+ (spec Table: Technology Stack). All timestamps are UTC ISO 8601 strings produced only
  via `common.schemas.utc_now_iso()` — never call `datetime.now()` directly in this plan's code. ISO
  8601 strings compare correctly with plain `<`/`>=`, so this plan never converts them to epoch
  floats for range filtering (CSV export, alert-list time filters) — same convention Phase 2's
  calibration window filter already uses.
- **Table ownership:** this plan owns `admin_user` entirely (full read/write — no other phase touches
  it) and is the Event Store that owns `evidence` and `verdict`, per Phase 4's explicit statement
  ("`evidence` and `verdict` are normally written exactly once, by the (separate, later) Event Store
  subscribing to the bus") and Phase 3's identical statement. `host.risk_score` is written only by
  this plan (from `HOST_SCORE_UPDATED` messages) — `host.ip_address`/`mac_address`/`hostname`/
  `is_internal`/timestamps may already exist from an upstream `upsert_host`-style write in another
  phase; this plan only ever updates `risk_score` and `last_seen` on an existing or newly-upserted
  row, never `is_internal`. `block_entry`, `allowlist_entry` and `model_package` are read-only for
  this plan (owned by Phase 4's Enforcer and Phase 7's `ModelRegistry` respectively) with one
  narrow exception: `allowlist_entry` rows may be inserted/deleted here too, since FR-10.4 ("let the
  administrator add and remove devices from the allowlist") is this screen's job and Phase 4's own
  constraints say it only *seeds* 2-3 permanent rows at startup, not that it owns the table
  exclusively. `component_event` (Phase 5's watchdog) and `calibration_state`/`flow_record`
  (Phase 2) are read-only here. `config_setting` is read/written only through
  `common.config_loader.get()`/`update()` (Phase 1's shared surface — never raw SQL on this table).
- **No cross-phase `services/*` or `models/*` imports (established precedent, not new to this plan):**
  per the master roadmap's cross-cutting rule, only `common/` is a shared import surface between
  phases. Every other already-written plan that needed a small piece of another phase's service-local
  logic re-implemented it locally rather than importing across `services/` boundaries — Phase 4's
  `Enforcer._upsert_host()` duplicates (rather than imports) Phase 2's `upsert_host()`; Phase 3's
  `load_model_package()` reads `model_package` with raw SQL rather than importing a `ModelRegistry`.
  This plan follows the same convention twice: `services/dashboard/verdict_sync.py` is a byte-for-byte
  copy of Phase 4's `services/enforcer/verdict_sync.py::verdict_id_from_message_id()` (both must
  derive the identical `verdict_id` from the same `message_id` for the dual-write `INSERT OR IGNORE`
  to converge — see "Verdict dual-write reconciliation" below), and the Settings screen's model
  display reads `model_package` with raw SQL instead of importing Phase 7's `models.registry.
  ModelRegistry`.
- **Verdict dual-write reconciliation (closes the gap Phase 4 explicitly left open):** Phase 4's
  Global Constraints state "The Event Store's own future plan must replicate this exact function... 
  whichever of the two writers runs first wins the real row; the other's `INSERT OR IGNORE` is a
  no-op." This plan's Event Store does exactly that: for every `VERDICT` message with
  `action == "BLOCK"`, it computes `verdict_id = verdict_id_from_message_id(envelope["message_id"])`
  and runs `INSERT OR IGNORE INTO verdict (verdict_id, ...)` with that explicit id — identical to
  Enforcer's own insert for the same message — so the row this plan's Event Store would otherwise
  write for a BLOCK verdict and the row Enforcer already wrote converge on one, instead of leaving
  two divergent rows with different synthetic ids. For `ALERT`/`PASS` verdicts (no explicit id
  contention — Enforcer never writes those), this plan does a plain `INSERT INTO verdict` with an
  autoincrement id, exactly as it does for every `evidence` row.
- **Admin-command bus contract (a documented, intentionally one-sided integration point — same
  pattern as the dual-write exception above, not an oversight):** FR-9.5 ("unblock a device"),
  FR-10.5 ("reload rules / recalibrate on demand") require the dashboard to trigger actions owned by
  Enforcer (ipset) and the signature-bridge/mlscorer services (rule reload, recalibration) — all three
  already-written, sealed phases whose `main.py` consumer loops only subscribe to the streams their
  own plans defined (`STREAM_VERDICTS` for Enforcer; no admin-command stream exists anywhere yet).
  This plan adds a fifth Redis Stream, `STREAM_ADMIN_COMMANDS = "nidps:admin_commands"`, and three new
  `MessageType`s (`UNBLOCK_REQUESTED`, `RELOAD_RULES_REQUESTED`, `RECALIBRATE_REQUESTED`) to
  `common/`, and this plan's `services/dashboard/admin_commands.py` is the **publish side only**.
  Wiring a consumer for this stream into Enforcer's/mlscorer's/sigbridge's already-written `main.py`
  loops is explicitly out of scope for this plan — it is integration work for the master roadmap's
  Sprint 10 ("integration hardening"), exactly as that sprint already exists to close gaps like this
  one. Until that wiring lands, these three dashboard actions publish successfully and are durably
  queued on the stream (Redis Streams retain unacked entries) but have no visible effect — this is a
  known, documented limitation, not a bug in this plan.
- **Settings screen UC-12 scope note:** the spec's Settings screen covers "UC-07, UC-08, UC-09,
  UC-10, UC-12 (model version display)" — the parenthetical is the spec's own wording, and UC-12's
  actor is "Model Maintainer" operating Phase 7's `training.promote_model` CLI, not the Network
  Administrator who logs into this dashboard. This plan's Settings/Models tab is read-only display of
  `model_package` rows; it never calls `ModelRegistry.activate()`/`rollback()` or writes that table.
- **Password hashing:** PBKDF2-HMAC-SHA256 (stdlib `hashlib.pbkdf2_hmac`, no new dependency) with a
  random 16-byte salt and 210,000 iterations (OWASP's 2023 minimum recommendation for PBKDF2-SHA256),
  stored as the single string `admin_user.password_hash = "pbkdf2_sha256$<iterations>$<salt_hex>$
  <hash_hex>"` so the iteration count can be raised later without invalidating already-hashed rows.
- **Login does not reveal which field was wrong (FR-9.1):** `auth.authenticate()` returns the same
  generic `AuthResult(ok=False, reason="invalid_credentials")` whether the username doesn't exist or
  the password is wrong, and the same `locked` reason regardless of which triggered it. Lockout uses
  the already-existing `auth.lockout_attempts`/`auth.lockout_duration_s` config keys (Phase 1,
  `common/config_schema.py` — not new to this plan) against `admin_user.failed_attempts`/
  `locked_until`.
- **Session tokens, not JWT:** a session is a random 32-byte `secrets.token_urlsafe()` string used as
  a Redis key (`nidps:session:<token>` → `user_id`, TTL-refreshed on each authenticated request) —
  simplest mechanism satisfying FR-9.1 without adding a JWT dependency; sessions live only in Redis
  (same instance as the event bus), so a restart of the dashboard process does not invalidate active
  logins, matching FR-10.6's "no restart" spirit for the operator experience.
- **Live counters are two independent Redis Streams consumer groups, not shared state with other
  services' groups:** `"dashboard-live-stats"` on `STREAM_FLOWS` (alongside Phase 2's
  `"layer2-anomaly"` group) and `"dashboard-live-stats"` on `STREAM_VERDICTS` (alongside Phase 4's
  own internal consumption) — Redis Streams groups are independent by design (Phase 1's
  `EventBus.consume()` already supports multiple named groups per stream), so this never competes
  with or blocks another service's consumption of the same stream.
- **Testing:** SQLite `:memory:` via `common.db.migrate.connect(":memory:")` for all DB tests;
  `fakeredis.FakeRedis(decode_responses=True)` for all Redis-touching tests; FastAPI's `TestClient`
  (via `httpx`, added by this plan) for the API/WebSocket integration test — no test binds a real
  network port or requires a running Redis/uvicorn process.

---

## File Structure

```
services/
  dashboard/
    __init__.py
    auth.py              # hash_password()/verify_password(), authenticate() with lockout
    create_admin.py      # CLI: python -m services.dashboard.create_admin <user> <password>
    sessions.py           # SessionStore: create()/user_id_for()/revoke() over Redis
    verdict_sync.py        # verdict_id_from_message_id() -- byte-for-byte copy of Phase 4's
    event_store.py          # EventStore: persists evidence/verdict/host.risk_score from the bus
    live_stats.py            # LiveStats: in-memory flows/intrusions counters + active-blocks read
    config_api.py             # grouped config read/update, wrapping common.config_loader
    admin_commands.py          # publish UNBLOCK_REQUESTED / RELOAD_RULES_REQUESTED / RECALIBRATE_REQUESTED
    queries.py                  # alerts+evidence, blocked hosts, allowlist, hosts, health, models (reads)
    csv_export.py                # FR-11.3: alerts/blocks CSV for a time range
    api.py                        # FastAPI app: routes + WebSocket push
    main.py                        # entry point: uvicorn + EventStore thread + live-stats thread + heartbeat
common/
  bus.py                # MODIFIED: add STREAM_ADMIN_COMMANDS
  bus_messages.py        # MODIFIED: add UNBLOCK_REQUESTED, RELOAD_RULES_REQUESTED, RECALIBRATE_REQUESTED
tests/
  unit/
    test_bus_admin_commands.py        # MODIFIED (STREAM_ADMIN_COMMANDS + new MessageTypes coverage)
    test_dashboard_auth.py
    test_dashboard_sessions.py
    test_dashboard_verdict_sync.py
    test_dashboard_event_store.py
    test_dashboard_live_stats.py
    test_dashboard_config_api.py
    test_dashboard_admin_commands.py
    test_dashboard_queries.py
    test_dashboard_csv_export.py
  integration/
    test_dashboard_api.py
```

---

## Task 1: Project dependencies and package scaffolding

**Files:**
- Modify: `requirements.txt`
- Create: `services/dashboard/__init__.py`

**Interfaces:**
- Consumes: nothing.
- Produces: an installable `fastapi`/`uvicorn`/`httpx` environment every later task in this plan
  assumes already exists.

- [ ] **Step 1: Append to `requirements.txt`**

```
fastapi>=0.110,<1.0
uvicorn[standard]>=0.27,<1.0
httpx>=0.27,<1.0
```

- [ ] **Step 2: Install the new dependencies**

Run:
```bash
.venv/Scripts/pip install -r requirements.txt
```
Expected: `fastapi`, `uvicorn`, `httpx` and their transitive dependencies (including `websockets`,
pulled in by `uvicorn[standard]`) install without error.

- [ ] **Step 3: Create `services/dashboard/__init__.py`**

```python
```

- [ ] **Step 4: Commit**

```bash
git add requirements.txt services/dashboard/__init__.py
git commit -m "chore: add FastAPI/uvicorn/httpx dependencies for the dashboard service"
```

---

## Task 2: Admin-command bus contract (`common/bus.py`, `common/bus_messages.py`)

**Files:**
- Modify: `common/bus.py`
- Modify: `common/bus_messages.py`
- Create: `tests/unit/test_bus_admin_commands.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `common.bus.STREAM_ADMIN_COMMANDS = "nidps:admin_commands"`;
  `common.bus_messages.MessageType.{UNBLOCK_REQUESTED, RELOAD_RULES_REQUESTED,
  RECALIBRATE_REQUESTED}`. Task 9's `admin_commands.py` publishes through these — see Global
  Constraints' "Admin-command bus contract" note for why no consumer exists yet.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_bus_admin_commands.py
import fakeredis

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope


def test_stream_admin_commands_name():
    assert STREAM_ADMIN_COMMANDS == "nidps:admin_commands"


def test_publish_and_consume_admin_command_round_trip():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(
        STREAM_ADMIN_COMMANDS,
        encode_envelope(MessageType.UNBLOCK_REQUESTED, {"ip": "10.0.0.5", "requested_by": 1}),
    )

    received = []
    bus.consume(
        STREAM_ADMIN_COMMANDS, group="test", consumer="c1", handler=received.append, block_ms=100
    )

    envelope = decode_envelope(received[0])
    assert envelope["type"] == MessageType.UNBLOCK_REQUESTED.value
    assert envelope["payload"]["ip"] == "10.0.0.5"


def test_reload_rules_and_recalibrate_message_types_exist():
    assert MessageType.RELOAD_RULES_REQUESTED.value == "reload_rules_requested"
    assert MessageType.RECALIBRATE_REQUESTED.value == "recalibrate_requested"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_bus_admin_commands.py -v`
Expected: FAIL — `ImportError: cannot import name 'STREAM_ADMIN_COMMANDS' from 'common.bus'`

- [ ] **Step 3: Add the constant to `common/bus.py`**

Add alongside the existing stream constants:
```python
STREAM_ADMIN_COMMANDS = "nidps:admin_commands"
```

- [ ] **Step 4: Add the message types to `common/bus_messages.py`**

Add to the `MessageType` enum:
```python
    UNBLOCK_REQUESTED = "unblock_requested"
    RELOAD_RULES_REQUESTED = "reload_rules_requested"
    RECALIBRATE_REQUESTED = "recalibrate_requested"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_bus_admin_commands.py -v`
Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add common/bus.py common/bus_messages.py tests/unit/test_bus_admin_commands.py
git commit -m "feat: add STREAM_ADMIN_COMMANDS and admin-command message types"
```

---

## Task 3: Password hashing and admin bootstrap (`services/dashboard/auth.py`, `create_admin.py`)

**Files:**
- Create: `services/dashboard/auth.py`
- Create: `services/dashboard/create_admin.py`
- Test: `tests/unit/test_dashboard_auth.py`

**Interfaces:**
- Consumes: `common.db.migrate.connect` (Phase 1), stdlib `hashlib`/`hmac`/`secrets`.
- Produces: `hash_password(password: str) -> str`; `verify_password(password: str, stored: str) ->
  bool`; `create_admin_user(conn, username: str, password: str) -> int` (raises `ValueError` if the
  username already exists). Task 4's `authenticate()` calls `verify_password()`; the CLI entry point
  is how an operator seeds the first login (no other phase or task auto-creates `admin_user` rows).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_auth.py
import pytest

from common.db.migrate import connect
from services.dashboard.auth import create_admin_user, hash_password, verify_password


def test_hash_password_produces_verifiable_hash():
    stored = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", stored) is True


def test_verify_password_rejects_wrong_password():
    stored = hash_password("correct horse battery staple")

    assert verify_password("wrong password", stored) is False


def test_two_hashes_of_the_same_password_differ_by_salt():
    assert hash_password("same") != hash_password("same")


def test_create_admin_user_inserts_row_with_hashed_password():
    conn = connect(":memory:")

    user_id = create_admin_user(conn, "admin", "s3cret-password")

    row = conn.execute(
        "SELECT username, password_hash, failed_attempts FROM admin_user WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    assert row[0] == "admin"
    assert row[1] != "s3cret-password"
    assert row[2] == 0


def test_create_admin_user_rejects_duplicate_username():
    conn = connect(":memory:")
    create_admin_user(conn, "admin", "first-password")

    with pytest.raises(ValueError):
        create_admin_user(conn, "admin", "second-password")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.auth'`

- [ ] **Step 3: Write `services/dashboard/auth.py`**

```python
"""Password hashing (FR-9.1) and the admin_user table this plan owns exclusively. PBKDF2-HMAC-
SHA256 via stdlib hashlib -- no bcrypt/argon2 dependency needed for a single-admin device."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

from common.schemas import utc_now_iso

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 210_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALGORITHM}${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations_s, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if algorithm != _ALGORITHM:
        return False
    iterations = int(iterations_s)
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def create_admin_user(conn: sqlite3.Connection, username: str, password: str) -> int:
    existing = conn.execute(
        "SELECT user_id FROM admin_user WHERE username = ?", (username,)
    ).fetchone()
    if existing is not None:
        raise ValueError(f"admin_user {username!r} already exists")
    cursor = conn.execute(
        "INSERT INTO admin_user (username, password_hash, failed_attempts, created_at) "
        "VALUES (?, ?, 0, ?)",
        (username, hash_password(password), utc_now_iso()),
    )
    conn.commit()
    return cursor.lastrowid
```

- [ ] **Step 4: Write `services/dashboard/create_admin.py`**

```python
"""CLI to seed the first (or an additional) admin_user row. Usage:
    python -m services.dashboard.create_admin <db_path> <username> <password>
No other task in this plan auto-creates admin_user rows -- the operator runs this once, during
initial device setup, outside the web flow (there is no "register" screen -- FR-9.1 only requires
login, not self-service account creation)."""
from __future__ import annotations

import argparse
import sys

from common.db.migrate import connect
from services.dashboard.auth import create_admin_user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a NIDPS dashboard admin user")
    parser.add_argument("db_path")
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()

    conn = connect(args.db_path)
    try:
        user_id = create_admin_user(conn, args.username, args.password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Created admin_user {args.username!r} with user_id={user_id}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_auth.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add services/dashboard/auth.py services/dashboard/create_admin.py tests/unit/test_dashboard_auth.py
git commit -m "feat: add password hashing and admin_user bootstrap CLI"
```

---

## Task 4: Login with lockout (`services/dashboard/auth.py` — extended)

**Files:**
- Modify: `services/dashboard/auth.py`
- Test: `tests/unit/test_dashboard_auth.py` (extended)

**Interfaces:**
- Consumes: `services.dashboard.auth.verify_password` (this task's Task 3 half),
  `common.config_loader.get` (`auth.lockout_attempts`, `auth.lockout_duration_s` — both already
  defined in Phase 1's `common/config_schema.py`), `common.schemas.utc_now_iso` (Phase 1).
- Produces: `AuthResult` dataclass (`ok: bool`, `user_id: Optional[int]`, `reason: Optional[str]`);
  `authenticate(conn, config_get, username: str, password: str, now_fn=utc_now_iso) -> AuthResult`.
  Task 12's `/api/login` route calls this exclusively — FR-9.1's "doesn't reveal which field was
  wrong" and lockout-after-N-failures live only here.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_auth.py (append)
from common.config_loader import seed_defaults, update
from services.dashboard.auth import authenticate, create_admin_user


def _config_get(conn):
    def get(key):
        from common.config_loader import get as _get
        return _get(conn, key)
    return get


def test_authenticate_succeeds_with_correct_credentials():
    conn = connect(":memory:")
    seed_defaults(conn)
    user_id = create_admin_user(conn, "admin", "correct-password")

    result = authenticate(conn, _config_get(conn), "admin", "correct-password")

    assert result.ok is True
    assert result.user_id == user_id


def test_authenticate_fails_with_generic_reason_for_wrong_password():
    conn = connect(":memory:")
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")

    result = authenticate(conn, _config_get(conn), "admin", "wrong-password")

    assert result.ok is False
    assert result.reason == "invalid_credentials"


def test_authenticate_fails_with_same_generic_reason_for_unknown_username():
    conn = connect(":memory:")
    seed_defaults(conn)

    result = authenticate(conn, _config_get(conn), "nobody", "anything")

    assert result.ok is False
    assert result.reason == "invalid_credentials"


def test_authenticate_locks_account_after_configured_failed_attempts():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "auth.lockout_attempts", 3)
    create_admin_user(conn, "admin", "correct-password")

    for _ in range(3):
        authenticate(conn, _config_get(conn), "admin", "wrong-password")

    result = authenticate(conn, _config_get(conn), "admin", "correct-password")

    assert result.ok is False
    assert result.reason == "locked"


def test_authenticate_unlocks_after_lockout_duration_elapses():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "auth.lockout_attempts", 1)
    update(conn, "auth.lockout_duration_s", 300)
    create_admin_user(conn, "admin", "correct-password")

    authenticate(conn, _config_get(conn), "admin", "wrong-password", now_fn=lambda: "2026-01-01T00:00:00.000000Z")
    locked_out = authenticate(
        conn, _config_get(conn), "admin", "correct-password",
        now_fn=lambda: "2026-01-01T00:00:01.000000Z",
    )
    after_window = authenticate(
        conn, _config_get(conn), "admin", "correct-password",
        now_fn=lambda: "2026-01-01T00:05:01.000000Z",
    )

    assert locked_out.ok is False
    assert locked_out.reason == "locked"
    assert after_window.ok is True


def test_authenticate_resets_failed_attempts_on_success():
    conn = connect(":memory:")
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")

    authenticate(conn, _config_get(conn), "admin", "wrong-password")
    authenticate(conn, _config_get(conn), "admin", "correct-password")

    row = conn.execute("SELECT failed_attempts FROM admin_user WHERE username = 'admin'").fetchone()
    assert row[0] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_auth.py -v`
Expected: FAIL — `ImportError: cannot import name 'authenticate' from 'services.dashboard.auth'`

- [ ] **Step 3: Append to `services/dashboard/auth.py`**

```python
from dataclasses import dataclass
from typing import Callable, Optional

from common.schemas import utc_now_iso


@dataclass
class AuthResult:
    ok: bool
    user_id: Optional[int] = None
    reason: Optional[str] = None


def authenticate(
    conn: sqlite3.Connection,
    config_get: Callable[[str], object],
    username: str,
    password: str,
    now_fn: Callable[[], str] = utc_now_iso,
) -> AuthResult:
    row = conn.execute(
        "SELECT user_id, password_hash, failed_attempts, locked_until FROM admin_user "
        "WHERE username = ?",
        (username,),
    ).fetchone()
    now = now_fn()

    if row is None:
        return AuthResult(ok=False, reason="invalid_credentials")

    user_id, password_hash, failed_attempts, locked_until = row
    if locked_until is not None and now < locked_until:
        return AuthResult(ok=False, reason="locked")

    if not verify_password(password, password_hash):
        failed_attempts += 1
        lockout_attempts = int(config_get("auth.lockout_attempts"))
        new_locked_until = None
        if failed_attempts >= lockout_attempts:
            lockout_duration_s = int(config_get("auth.lockout_duration_s"))
            new_locked_until = _add_seconds(now, lockout_duration_s)
        conn.execute(
            "UPDATE admin_user SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
            (failed_attempts, new_locked_until, user_id),
        )
        conn.commit()
        return AuthResult(
            ok=False, reason="locked" if new_locked_until else "invalid_credentials"
        )

    conn.execute(
        "UPDATE admin_user SET failed_attempts = 0, locked_until = NULL, last_login = ? "
        "WHERE user_id = ?",
        (now, user_id),
    )
    conn.commit()
    return AuthResult(ok=True, user_id=user_id)


def _add_seconds(iso_ts: str, seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%S.%f%z" if iso_ts.endswith("Z") is False else "%Y-%m-%dT%H:%M:%S.%fZ")
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return (dt + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_auth.py -v`
Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/auth.py tests/unit/test_dashboard_auth.py
git commit -m "feat: add login authentication with generic failure reasons and lockout (FR-9.1)"
```

---

## Task 5: Redis session store (`services/dashboard/sessions.py`)

**Files:**
- Create: `services/dashboard/sessions.py`
- Test: `tests/unit/test_dashboard_sessions.py`

**Interfaces:**
- Consumes: a redis-py-compatible client (real or `fakeredis`), stdlib `secrets`.
- Produces: `SessionStore` class with `__init__(self, redis_client, ttl_s: int = 1800)`,
  `create(self, user_id: int) -> str` (returns the opaque token), `user_id_for(self, token: str) ->
  Optional[int]` (also refreshes the TTL — "sliding" session), `revoke(self, token: str) -> None`.
  Task 12's FastAPI dependency calls `user_id_for()` on every authenticated request.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_sessions.py
import fakeredis

from services.dashboard.sessions import SessionStore


def test_create_then_user_id_for_round_trip():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    token = store.create(user_id=7)

    assert store.user_id_for(token) == 7


def test_user_id_for_unknown_token_is_none():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    assert store.user_id_for("not-a-real-token") is None


def test_revoke_invalidates_token():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))
    token = store.create(user_id=7)

    store.revoke(token)

    assert store.user_id_for(token) is None


def test_two_sessions_have_different_tokens():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    assert store.create(user_id=1) != store.create(user_id=1)


def test_user_id_for_refreshes_ttl():
    client = fakeredis.FakeRedis(decode_responses=True)
    store = SessionStore(client, ttl_s=1800)
    token = store.create(user_id=7)

    client.expire(f"nidps:session:{token}", 5)
    store.user_id_for(token)

    assert client.ttl(f"nidps:session:{token}") > 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_sessions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.sessions'`

- [ ] **Step 3: Write `services/dashboard/sessions.py`**

```python
"""Opaque, Redis-backed session tokens (FR-9.1). A sliding TTL means an active admin session never
expires mid-use, but an idle browser tab is logged out after ttl_s of inactivity."""
from __future__ import annotations

import secrets
from typing import Optional

_KEY_PREFIX = "nidps:session:"


class SessionStore:
    def __init__(self, redis_client, ttl_s: int = 1800):
        self._client = redis_client
        self._ttl_s = ttl_s

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        self._client.set(f"{_KEY_PREFIX}{token}", str(user_id), ex=self._ttl_s)
        return token

    def user_id_for(self, token: str) -> Optional[int]:
        key = f"{_KEY_PREFIX}{token}"
        value = self._client.get(key)
        if value is None:
            return None
        self._client.expire(key, self._ttl_s)
        return int(value)

    def revoke(self, token: str) -> None:
        self._client.delete(f"{_KEY_PREFIX}{token}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_sessions.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/sessions.py tests/unit/test_dashboard_sessions.py
git commit -m "feat: add Redis-backed dashboard session store"
```

---

## Task 6: Verdict-id replica (`services/dashboard/verdict_sync.py`)

**Files:**
- Create: `services/dashboard/verdict_sync.py`
- Test: `tests/unit/test_dashboard_verdict_sync.py`

**Interfaces:**
- Consumes: stdlib `uuid`.
- Produces: `verdict_id_from_message_id(message_id: str) -> int`. Deliberately identical to Phase
  4's `services/enforcer/verdict_sync.py` function of the same name — see Global Constraints'
  "Verdict dual-write reconciliation."

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_dashboard_verdict_sync.py
import uuid

from services.dashboard.verdict_sync import verdict_id_from_message_id


def test_same_message_id_always_derives_same_verdict_id():
    message_id = str(uuid.uuid4())

    assert verdict_id_from_message_id(message_id) == verdict_id_from_message_id(message_id)


def test_derived_id_is_a_positive_63_bit_integer():
    verdict_id = verdict_id_from_message_id(str(uuid.uuid4()))

    assert 0 <= verdict_id < 2**63


def test_matches_the_enforcer_phase_derivation_exactly():
    message_id = "123e4567-e89b-12d3-a456-426614174000"

    assert verdict_id_from_message_id(message_id) == (
        uuid.UUID(message_id).int & 0x7FFFFFFFFFFFFFFF
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_verdict_sync.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.verdict_sync'`

- [ ] **Step 3: Write `services/dashboard/verdict_sync.py`**

```python
"""Byte-for-byte copy of services/enforcer/verdict_sync.py::verdict_id_from_message_id() (Phase
4). Both writers must derive the identical verdict_id from the same bus envelope's message_id so
their respective INSERT OR IGNORE INTO verdict (verdict_id, ...) calls converge on one row instead
of two. See this plan's Global Constraints, 'Verdict dual-write reconciliation'."""
from __future__ import annotations

import uuid


def verdict_id_from_message_id(message_id: str) -> int:
    return uuid.UUID(message_id).int & 0x7FFFFFFFFFFFFFFF
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_verdict_sync.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/verdict_sync.py tests/unit/test_dashboard_verdict_sync.py
git commit -m "feat: add verdict_id_from_message_id replica for Event Store dual-write reconciliation"
```

---

## Task 7: Event Store (`services/dashboard/event_store.py`)

**Files:**
- Create: `services/dashboard/event_store.py`
- Test: `tests/unit/test_dashboard_event_store.py`

**Interfaces:**
- Consumes: `common.bus.{EventBus, STREAM_EVIDENCE, STREAM_VERDICTS, STREAM_HOST_SCORES}` (Phase
  1/4), `common.bus_messages.{MessageType, decode_envelope}` (Phase 1), `common.schemas.utc_now_iso`
  (Phase 1), `services.dashboard.verdict_sync.verdict_id_from_message_id` (Task 6).
- Produces: `EventStore` class with `__init__(self, conn, bus)`, `handle_evidence(self, raw: str) ->
  None`, `handle_verdict(self, raw: str) -> None`, `handle_host_score(self, raw: str) -> None`,
  `consume_once(self, block_ms: int = 1000) -> None` (one poll of all three streams, for tests and
  for Task 13's main loop to call repeatedly). This is the database-writing role the master roadmap
  and Phases 3/4 both call "the (separate, later) Event Store."

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_event_store.py
import uuid

import fakeredis

from common.bus import STREAM_EVIDENCE, STREAM_HOST_SCORES, STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.schemas import Action, Evidence, EvidenceType, Layer, Verdict
from services.dashboard.event_store import EventStore
from services.dashboard.verdict_sync import verdict_id_from_message_id


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_handle_evidence_writes_row_and_upserts_host():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    ev = Evidence(
        source=Layer.L1_SIGNATURE, flow_id="42", host_ip="10.0.0.5",
        kind=EvidenceType.SIGNATURE, strength=1.0, weight=3.0, signature_id=2032754,
    )
    raw = encode_envelope(MessageType.EVIDENCE, ev)

    store.handle_evidence(raw)

    row = conn.execute(
        "SELECT layer, evidence_type, signature_id, score, weight FROM evidence"
    ).fetchone()
    assert row == ("L1", "SIGNATURE", 2032754, 1.0, 3.0)
    host = conn.execute("SELECT ip_address FROM host WHERE ip_address = '10.0.0.5'").fetchone()
    assert host is not None


def test_handle_verdict_writes_alert_row_with_autoincrement_id():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    verdict = Verdict(
        action=Action.ALERT, layers=["L2"], explanation="anomaly above threshold",
        flow_id="7", host_ip="10.0.0.9",
    )
    raw = encode_envelope(MessageType.VERDICT, verdict)

    store.handle_verdict(raw)

    row = conn.execute("SELECT decision, explanation FROM verdict").fetchone()
    assert row == ("ALERT", "anomaly above threshold")


def test_handle_verdict_block_uses_deterministic_id_and_is_idempotent_with_enforcer():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    message_id = str(uuid.uuid4())
    verdict = Verdict(
        action=Action.BLOCK, layers=["L1", "L3"], explanation="brute force",
        flow_id="3", host_ip="10.0.0.8",
    )
    raw = encode_envelope(MessageType.VERDICT, verdict)
    # simulate the envelope's real message_id being the one Enforcer also saw
    import json
    envelope = json.loads(raw)
    envelope["message_id"] = message_id
    raw = json.dumps(envelope)

    # Enforcer's own synchronous insert happens first, with the same derived id:
    expected_id = verdict_id_from_message_id(message_id)
    host_id = conn.execute(
        "INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.8', 1) RETURNING host_id"
    ).fetchone()[0]
    conn.execute(
        "INSERT OR IGNORE INTO verdict (verdict_id, host_id, decision, layers, explanation, created_at) "
        "VALUES (?, ?, 'BLOCK', '[]', 'brute force', '2026-01-01T00:00:00.000000Z')",
        (expected_id, host_id),
    )
    conn.commit()

    store.handle_verdict(raw)  # Event Store's own write must be a no-op on the same row

    count = conn.execute("SELECT COUNT(*) FROM verdict").fetchone()[0]
    assert count == 1
    row = conn.execute("SELECT verdict_id FROM verdict").fetchone()
    assert row[0] == expected_id


def test_handle_host_score_updates_host_risk_score():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    conn.execute("INSERT INTO host (ip_address, is_internal, risk_score) VALUES ('10.0.0.5', 1, 0)")
    conn.commit()
    raw = encode_envelope(
        MessageType.HOST_SCORE_UPDATED, {"host_ip": "10.0.0.5", "risk_score": 6.4}
    )

    store.handle_host_score(raw)

    score = conn.execute("SELECT risk_score FROM host WHERE ip_address = '10.0.0.5'").fetchone()[0]
    assert score == 6.4


def test_handle_host_score_upserts_unknown_host():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    raw = encode_envelope(
        MessageType.HOST_SCORE_UPDATED, {"host_ip": "10.0.0.77", "risk_score": 2.0}
    )

    store.handle_host_score(raw)

    row = conn.execute("SELECT risk_score FROM host WHERE ip_address = '10.0.0.77'").fetchone()
    assert row == (2.0,)


def test_consume_once_drains_all_three_streams():
    conn = connect(":memory:")
    bus = _bus()
    store = EventStore(conn, bus)
    ev = Evidence(
        source=Layer.L2_ANOMALY, flow_id="1", host_ip="10.0.0.1",
        kind=EvidenceType.ANOMALY, strength=0.8, weight=2.0,
    )
    verdict = Verdict(action=Action.PASS, layers=[], explanation="", host_ip="10.0.0.1")
    bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
    bus.publish(STREAM_VERDICTS, encode_envelope(MessageType.VERDICT, verdict))
    bus.publish(
        STREAM_HOST_SCORES,
        encode_envelope(MessageType.HOST_SCORE_UPDATED, {"host_ip": "10.0.0.1", "risk_score": 1.5}),
    )

    store.consume_once(block_ms=100)

    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM verdict").fetchone()[0] == 1
    assert conn.execute("SELECT risk_score FROM host WHERE ip_address='10.0.0.1'").fetchone()[0] == 1.5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_event_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.event_store'`

- [ ] **Step 3: Write `services/dashboard/event_store.py`**

```python
"""EventStore: the Event Store named throughout the master roadmap and Phases 3/4's Global
Constraints as "the (separate, later) Event Store subscribing to the bus". Owns evidence and
verdict (FR-11.1), and host.risk_score (FR-6.3's persisted side). Reconciles the one dual-write
case -- BLOCK verdicts, which Enforcer also writes synchronously -- via the shared deterministic
id in verdict_sync.py so INSERT OR IGNORE converges on a single row from either writer."""
from __future__ import annotations

import json
import sqlite3

from common.bus import STREAM_EVIDENCE, STREAM_HOST_SCORES, STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, decode_envelope
from common.schemas import utc_now_iso

from services.dashboard.verdict_sync import verdict_id_from_message_id

_CONSUMER_GROUP = "dashboard-event-store"


class EventStore:
    def __init__(self, conn: sqlite3.Connection, bus: EventBus, consumer_name: str = "event-store-1"):
        self._conn = conn
        self._bus = bus
        self._consumer = consumer_name

    def _upsert_host(self, ip: str) -> int:
        now = utc_now_iso()
        self._conn.execute(
            "INSERT OR IGNORE INTO host (ip_address, is_internal, first_seen, last_seen) "
            "VALUES (?, 1, ?, ?)",
            (ip, now, now),
        )
        self._conn.execute("UPDATE host SET last_seen = ? WHERE ip_address = ?", (now, ip))
        return self._conn.execute(
            "SELECT host_id FROM host WHERE ip_address = ?", (ip,)
        ).fetchone()[0]

    def handle_evidence(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        payload = envelope["payload"]
        host_id = self._upsert_host(payload["host_ip"])
        flow_id = int(payload["flow_id"]) if payload.get("flow_id") is not None else None
        self._conn.execute(
            """INSERT INTO evidence
               (flow_id, host_id, layer, evidence_type, signature_id, score, predicted_class,
                confidence, weight, model_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow_id, host_id, payload["source"], payload["kind"], payload.get("signature_id"),
                payload.get("strength"), payload.get("predicted_class"), payload.get("confidence"),
                payload["weight"], payload.get("model_id"), payload.get("timestamp", utc_now_iso()),
            ),
        )
        self._conn.commit()

    def handle_verdict(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        payload = envelope["payload"]
        host_id = self._upsert_host(payload["host_ip"]) if payload.get("host_ip") else None
        flow_id = int(payload["flow_id"]) if payload.get("flow_id") is not None else None
        layers = json.dumps(payload.get("layers", []))
        created_at = payload.get("timestamp", utc_now_iso())

        if payload["action"] == "BLOCK":
            verdict_id = verdict_id_from_message_id(envelope["message_id"])
            self._conn.execute(
                """INSERT OR IGNORE INTO verdict
                   (verdict_id, flow_id, host_id, decision, layers, attack_class, explanation,
                    created_at)
                   VALUES (?, ?, ?, 'BLOCK', ?, ?, ?, ?)""",
                (verdict_id, flow_id, host_id, layers, payload.get("attack_class"),
                 payload["explanation"], created_at),
            )
        else:
            self._conn.execute(
                """INSERT INTO verdict
                   (flow_id, host_id, decision, layers, attack_class, explanation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (flow_id, host_id, payload["action"], layers, payload.get("attack_class"),
                 payload["explanation"], created_at),
            )
        self._conn.commit()

    def handle_host_score(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        payload = envelope["payload"]
        host_id = self._upsert_host(payload["host_ip"])
        self._conn.execute(
            "UPDATE host SET risk_score = ? WHERE host_id = ?", (payload["risk_score"], host_id)
        )
        self._conn.commit()

    def consume_once(self, block_ms: int = 1000) -> None:
        self._bus.consume(
            STREAM_EVIDENCE, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self.handle_evidence, block_ms=block_ms,
        )
        self._bus.consume(
            STREAM_VERDICTS, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self.handle_verdict, block_ms=block_ms,
        )
        self._bus.consume(
            STREAM_HOST_SCORES, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self.handle_host_score, block_ms=block_ms,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_event_store.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/event_store.py tests/unit/test_dashboard_event_store.py
git commit -m "feat: add Event Store (evidence/verdict/host.risk_score persistence from the bus)"
```

---

## Task 8: Live in-memory counters (`services/dashboard/live_stats.py`)

**Files:**
- Create: `services/dashboard/live_stats.py`
- Test: `tests/unit/test_dashboard_live_stats.py`

**Interfaces:**
- Consumes: `common.bus.{EventBus, STREAM_FLOWS, STREAM_VERDICTS}` (Phase 2/4),
  `common.bus_messages.decode_envelope` (Phase 1).
- Produces: `LiveStats` class with `__init__(self, conn, bus)`, `consume_once(self, block_ms:
  int = 1000) -> None`, `snapshot(self) -> dict` (`{"flows_analyzed": int, "intrusions_detected":
  int, "active_blocks": int}`). Implements the spec's explicit design note (Section 4.9) that live
  counters are kept in memory/on the bus, not queried from the database, for the Overview screen's
  `[ SYSTEM SUMMARY ]` panel (FR-9.2).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_live_stats.py
import fakeredis

from common.bus import STREAM_FLOWS, STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from services.dashboard.live_stats import LiveStats


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_snapshot_starts_at_zero():
    conn = connect(":memory:")
    stats = LiveStats(conn, _bus())

    snap = stats.snapshot()

    assert snap == {"flows_analyzed": 0, "intrusions_detected": 0, "active_blocks": 0}


def test_flow_ready_messages_increment_flows_analyzed():
    conn = connect(":memory:")
    bus = _bus()
    stats = LiveStats(conn, bus)
    bus.publish(STREAM_FLOWS, encode_envelope(MessageType.FLOW_READY, {"flow_id": 1, "host_ip": "10.0.0.1"}))
    bus.publish(STREAM_FLOWS, encode_envelope(MessageType.FLOW_READY, {"flow_id": 2, "host_ip": "10.0.0.1"}))

    stats.consume_once(block_ms=100)

    assert stats.snapshot()["flows_analyzed"] == 2


def test_alert_and_block_verdicts_increment_intrusions_detected_but_pass_does_not():
    conn = connect(":memory:")
    bus = _bus()
    stats = LiveStats(conn, bus)
    for action in ("ALERT", "BLOCK", "PASS"):
        bus.publish(
            STREAM_VERDICTS,
            encode_envelope(MessageType.VERDICT, {"action": action, "layers": [], "explanation": "x"}),
        )

    stats.consume_once(block_ms=100)

    assert stats.snapshot()["intrusions_detected"] == 2


def test_active_blocks_reads_from_database():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, explanation) VALUES (?, 'BLOCK', '[]', 'x')",
        (host_id,),
    )
    verdict_id = conn.execute("SELECT verdict_id FROM verdict").fetchone()[0]
    conn.execute(
        "INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time, "
        "expires_at, status) VALUES (?, ?, 1, 300, '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'ACTIVE')",
        (host_id, verdict_id),
    )
    conn.commit()
    stats = LiveStats(conn, _bus())

    assert stats.snapshot()["active_blocks"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_live_stats.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.live_stats'`

- [ ] **Step 3: Write `services/dashboard/live_stats.py`**

```python
"""In-memory live counters for the Overview screen's [SYSTEM SUMMARY] panel (FR-9.2). Per spec
Section 4.9: "Live counters shown on the dashboard are kept in memory and on the event bus rather
than in the database" -- flows_analyzed/intrusions_detected are tallied from their own
"dashboard-live-stats" consumer group (independent of every other service's group on the same
streams), and only active_blocks is a cheap COUNT(*) read of block_entry (the one counter that
isn't naturally bus-derived and is inexpensive to read directly)."""
from __future__ import annotations

import sqlite3

from common.bus import STREAM_FLOWS, STREAM_VERDICTS, EventBus
from common.bus_messages import decode_envelope

_CONSUMER_GROUP = "dashboard-live-stats"


class LiveStats:
    def __init__(self, conn: sqlite3.Connection, bus: EventBus, consumer_name: str = "live-stats-1"):
        self._conn = conn
        self._bus = bus
        self._consumer = consumer_name
        self._flows_analyzed = 0
        self._intrusions_detected = 0

    def _on_flow(self, raw: str) -> None:
        decode_envelope(raw)  # validates envelope schema version
        self._flows_analyzed += 1

    def _on_verdict(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        if envelope["payload"]["action"] in ("ALERT", "BLOCK"):
            self._intrusions_detected += 1

    def consume_once(self, block_ms: int = 1000) -> None:
        self._bus.consume(
            STREAM_FLOWS, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self._on_flow, block_ms=block_ms,
        )
        self._bus.consume(
            STREAM_VERDICTS, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self._on_verdict, block_ms=block_ms,
        )

    def _active_blocks(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM block_entry WHERE status = 'ACTIVE'"
        ).fetchone()[0]

    def snapshot(self) -> dict:
        return {
            "flows_analyzed": self._flows_analyzed,
            "intrusions_detected": self._intrusions_detected,
            "active_blocks": self._active_blocks(),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_live_stats.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/live_stats.py tests/unit/test_dashboard_live_stats.py
git commit -m "feat: add in-memory live counters for the Overview screen"
```

---

## Task 9: Grouped config API (`services/dashboard/config_api.py`)

**Files:**
- Create: `services/dashboard/config_api.py`
- Test: `tests/unit/test_dashboard_config_api.py`

**Interfaces:**
- Consumes: `common.config_loader.{get, update}` (Phase 1), `common.config_schema.CONFIG_KEYS`
  (Phase 1).
- Produces: `SETTINGS_TABS: dict[str, list[str]]` (tab name → ordered list of `CONFIG_KEYS` key
  names — this plan's own grouping, since the spec names the four tabs visually but not which key
  belongs in which, per the Settings screen mockup's `[ DETECTION LAYERS ] [ THRESHOLDS ]
  [ PREVENTION & FAILURE ] [ RULES, CALIBRATION & MODELS ]` tab bar); `get_tab(conn, tab: str) ->
  list[dict]` (each dict: `key`, `value`, `default`, `min_value`, `max_value`); `update_setting(conn,
  key: str, value, user_id: int) -> None` (thin wrapper over `common.config_loader.update` — FR-10.6
  audit logging already happens there).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_config_api.py
import pytest

from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.dashboard.config_api import SETTINGS_TABS, get_tab, update_setting


def test_every_config_key_is_assigned_to_exactly_one_tab():
    from common.config_schema import CONFIG_KEYS_BY_NAME

    assigned = [key for keys in SETTINGS_TABS.values() for key in keys]
    assert sorted(assigned) == sorted(CONFIG_KEYS_BY_NAME.keys())
    assert len(assigned) == len(set(assigned))  # no key in two tabs


def test_get_tab_returns_detection_layers_with_current_values():
    conn = connect(":memory:")
    seed_defaults(conn)

    rows = get_tab(conn, "detection_layers")

    keys = {row["key"] for row in rows}
    assert "detection.layer1_enabled" in keys
    layer1 = next(row for row in rows if row["key"] == "detection.layer1_enabled")
    assert layer1["value"] is True
    assert layer1["default"] is True


def test_get_tab_raises_for_unknown_tab():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(KeyError):
        get_tab(conn, "no-such-tab")


def test_update_setting_writes_through_to_config_loader():
    conn = connect(":memory:")
    seed_defaults(conn)

    update_setting(conn, "risk.block_threshold", 7.0, user_id=1)

    rows = get_tab(conn, "thresholds")
    row = next(r for r in rows if r["key"] == "risk.block_threshold")
    assert row["value"] == 7.0


def test_update_setting_rejects_out_of_range_value():
    conn = connect(":memory:")
    seed_defaults(conn)

    with pytest.raises(ValueError):
        update_setting(conn, "risk.block_threshold", 999.0, user_id=1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_config_api.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.config_api'`

- [ ] **Step 3: Write `services/dashboard/config_api.py`**

```python
"""Grouped read/update view over common.config_loader (FR-10.1-10.3), matching the Settings
screen's four tabs: Detection Layers, Thresholds, Prevention & Failure, Rules/Calibration/Models.
The spec's mockup names the tabs but not the key-to-tab mapping -- this grouping is this plan's own
design choice, documented here rather than left implicit in route code."""
from __future__ import annotations

import sqlite3

from common.config_loader import get as config_get
from common.config_loader import update as config_update
from common.config_schema import CONFIG_KEYS_BY_NAME

SETTINGS_TABS: dict[str, list[str]] = {
    "detection_layers": [
        "detection.layer1_enabled",
        "detection.layer2_enabled",
        "detection.layer3_enabled",
        "network.active_timeout_s",
        "network.idle_timeout_s",
    ],
    "thresholds": [
        "anomaly.n_estimators",
        "anomaly.subsample_size",
        "exfil.ewma_alpha",
        "exfil.bucket_seconds",
        "exfil.k_std",
        "exfil.u_max_percentile",
        "beacon.min_connections",
        "beacon.cv_threshold",
        "fusion.theta_block",
        "fusion.theta_alert",
        "fusion.theta_c",
        "risk.half_life_s",
        "risk.block_threshold",
        "risk.weight_signature",
        "risk.weight_anomaly",
        "risk.weight_class",
        "risk.weight_exfil",
        "risk.weight_beacon",
    ],
    "prevention_and_failure": [
        "enforcement.base_block_s",
        "enforcement.max_block_s",
        "enforcement.rate_limit_per_minute",
        "failure_mode",
        "watchdog.heartbeat_interval_s",
        "watchdog.missed_heartbeats_threshold",
        "watchdog.cpu_high_watermark",
        "watchdog.cpu_low_watermark",
        "retention.flow_days",
        "auth.lockout_attempts",
        "auth.lockout_duration_s",
    ],
    "rules_calibration_models": [
        "anomaly.calibration_window_hours",
        "anomaly.calibration_percentile",
        "anomaly.calibration_min_samples",
        "anomaly.calibration_max_shift",
        "anomaly.recalibration_interval_days",
        "rules.update_interval_hours",
    ],
}


def get_tab(conn: sqlite3.Connection, tab: str) -> list[dict]:
    if tab not in SETTINGS_TABS:
        raise KeyError(f"Unknown settings tab: {tab!r}")
    rows = []
    for key in SETTINGS_TABS[tab]:
        spec = CONFIG_KEYS_BY_NAME[key]
        rows.append({
            "key": key,
            "value": config_get(conn, key),
            "default": spec.default,
            "min_value": spec.min_value,
            "max_value": spec.max_value,
        })
    return rows


def update_setting(conn: sqlite3.Connection, key: str, value, user_id: int) -> None:
    config_update(conn, key, value, user_id=user_id)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_config_api.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/config_api.py tests/unit/test_dashboard_config_api.py
git commit -m "feat: add grouped Settings-screen config API"
```

---

## Task 10: Admin command publisher (`services/dashboard/admin_commands.py`)

**Files:**
- Create: `services/dashboard/admin_commands.py`
- Test: `tests/unit/test_dashboard_admin_commands.py`

**Interfaces:**
- Consumes: `common.bus.{EventBus, STREAM_ADMIN_COMMANDS}` (Task 2), `common.bus_messages.
  {MessageType, encode_envelope}` (Task 2).
- Produces: `AdminCommands` class with `__init__(self, bus)`, `request_unblock(self, ip: str,
  requested_by: int) -> None`, `request_reload_rules(self, requested_by: int) -> None`,
  `request_recalibration(self, requested_by: int) -> None`. See Global Constraints' "Admin-command
  bus contract" for the documented scope of what happens after publish.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_admin_commands.py
import fakeredis

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, decode_envelope
from services.dashboard.admin_commands import AdminCommands


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_request_unblock_publishes_correct_message_type_and_payload():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_unblock("10.0.0.5", requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    envelope = decode_envelope(received[0])
    assert envelope["type"] == MessageType.UNBLOCK_REQUESTED.value
    assert envelope["payload"] == {"ip": "10.0.0.5", "requested_by": 1}


def test_request_reload_rules_publishes_correct_message_type():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_reload_rules(requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    assert decode_envelope(received[0])["type"] == MessageType.RELOAD_RULES_REQUESTED.value


def test_request_recalibration_publishes_correct_message_type():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_recalibration(requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    assert decode_envelope(received[0])["type"] == MessageType.RECALIBRATE_REQUESTED.value
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_admin_commands.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.admin_commands'`

- [ ] **Step 3: Write `services/dashboard/admin_commands.py`**

```python
"""Publish side of the admin-command bus contract (FR-9.5, FR-10.5). See this plan's Global
Constraints, 'Admin-command bus contract', for why no consumer exists yet -- this is a
documented, intentional half of a cross-phase integration point."""
from __future__ import annotations

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, encode_envelope


class AdminCommands:
    def __init__(self, bus: EventBus):
        self._bus = bus

    def request_unblock(self, ip: str, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.UNBLOCK_REQUESTED, {"ip": ip, "requested_by": requested_by}),
        )

    def request_reload_rules(self, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.RELOAD_RULES_REQUESTED, {"requested_by": requested_by}),
        )

    def request_recalibration(self, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.RECALIBRATE_REQUESTED, {"requested_by": requested_by}),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_admin_commands.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/admin_commands.py tests/unit/test_dashboard_admin_commands.py
git commit -m "feat: add admin-command publisher for unblock/reload-rules/recalibrate"
```

---

## Task 11: Read queries for Alerts, Blocked Hosts, Hosts, Health and Models screens (`services/dashboard/queries.py`)

**Files:**
- Create: `services/dashboard/queries.py`
- Test: `tests/unit/test_dashboard_queries.py`

**Interfaces:**
- Consumes: `common.schemas.utc_now_iso` (Phase 1).
- Produces: `list_alerts(conn, limit=50, host_ip=None, attack_class=None) -> list[dict]`;
  `alert_evidence(conn, verdict_id: int) -> list[dict]`; `list_blocked_hosts(conn) -> list[dict]`;
  `list_allowlist(conn) -> list[dict]`; `add_allowlist_entry(conn, address: str, description: str,
  added_by: int) -> int`; `remove_allowlist_entry(conn, entry_id: int) -> None`; `list_hosts(conn) ->
  list[dict]`; `component_health(conn) -> list[dict]`; `list_models(conn) -> list[dict]`. These back
  every read-only panel across the Alerts, Blocked Hosts & Allowlist, Overview (device list) and
  System Health screens, plus the Settings screen's read-only Models tab (see Global Constraints'
  "Settings screen UC-12 scope note").

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_queries.py
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
        "VALUES ('enforcer', 'RUNNING', NULL, NULL)"
    )
    conn.commit()

    health = queries.component_health(conn)

    assert health[0]["component"] == "enforcer"


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_queries.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.queries'`

- [ ] **Step 3: Write `services/dashboard/queries.py`**

```python
"""Read-only query helpers backing the Alerts, Blocked Hosts & Allowlist, Overview device list,
System Health, and Settings/Models screens (FR-9.3-9.7, FR-10.4). Reads model_package directly
with raw SQL rather than importing Phase 7's ModelRegistry -- see Global Constraints, 'No
cross-phase services/*or models/* imports'."""
from __future__ import annotations

import json
import sqlite3

from common.schemas import utc_now_iso


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_queries.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/queries.py tests/unit/test_dashboard_queries.py
git commit -m "feat: add read queries for alerts, blocked hosts, allowlist, hosts, health and models"
```

---

## Task 12: CSV export (`services/dashboard/csv_export.py`)

**Files:**
- Create: `services/dashboard/csv_export.py`
- Test: `tests/unit/test_dashboard_csv_export.py`

**Interfaces:**
- Consumes: nothing beyond stdlib `csv`/`io`.
- Produces: `export_alerts_csv(conn, start_iso: str, end_iso: str) -> str`; `export_blocks_csv(conn,
  start_iso: str, end_iso: str) -> str` (both return the full CSV text). FR-11.3.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_dashboard_csv_export.py
import csv
import io

from common.db.migrate import connect
from services.dashboard.csv_export import export_alerts_csv, export_blocks_csv


def test_export_alerts_csv_includes_header_and_rows_in_range():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, attack_class, explanation, created_at) "
        "VALUES (?, 'ALERT', '[\"L2\"]', 'ANOMALY', 'score above tau', '2026-03-10T00:00:00Z')",
        (host_id,),
    )
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, attack_class, explanation, created_at) "
        "VALUES (?, 'ALERT', '[\"L2\"]', 'ANOMALY', 'outside range', '2026-05-01T00:00:00Z')",
        (host_id,),
    )
    conn.commit()

    csv_text = export_alerts_csv(conn, "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z")

    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert reader[0]["explanation"] == "score above tau"
    assert reader[0]["host_ip"] == "10.0.0.5"


def test_export_blocks_csv_includes_header_and_rows_in_range():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.8', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, explanation, created_at) "
        "VALUES (?, 'BLOCK', '[]', 'x', '2026-03-10T00:00:00Z')",
        (host_id,),
    )
    verdict_id = conn.execute("SELECT verdict_id FROM verdict").fetchone()[0]
    conn.execute(
        "INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time, "
        "expires_at, status) VALUES (?, ?, 1, 300, '2026-03-10T00:00:00Z', '2026-03-10T00:05:00Z', 'EXPIRED')",
        (host_id, verdict_id),
    )
    conn.commit()

    csv_text = export_blocks_csv(conn, "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z")

    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert reader[0]["ip_address"] == "10.0.0.8"
    assert reader[0]["status"] == "EXPIRED"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_csv_export.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.csv_export'`

- [ ] **Step 3: Write `services/dashboard/csv_export.py`**

```python
"""CSV export of alerts and blocks for a chosen time period (FR-11.3). ISO 8601 strings compare
lexicographically, so range filtering never converts to epoch floats -- same convention as Phase
2's calibration window filter."""
from __future__ import annotations

import csv
import io
import sqlite3


def export_alerts_csv(conn: sqlite3.Connection, start_iso: str, end_iso: str) -> str:
    rows = conn.execute(
        """SELECT verdict.created_at, host.ip_address, verdict.decision, verdict.attack_class,
                  verdict.layers, verdict.explanation
           FROM verdict JOIN host ON host.host_id = verdict.host_id
           WHERE verdict.created_at >= ? AND verdict.created_at < ?
           ORDER BY verdict.created_at""",
        (start_iso, end_iso),
    ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["created_at", "host_ip", "decision", "attack_class", "layers", "explanation"])
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def export_blocks_csv(conn: sqlite3.Connection, start_iso: str, end_iso: str) -> str:
    rows = conn.execute(
        """SELECT block_entry.start_time, host.ip_address, block_entry.duration_s,
                  block_entry.offence_count, block_entry.status, block_entry.expires_at,
                  block_entry.released_at
           FROM block_entry JOIN host ON host.host_id = block_entry.host_id
           WHERE block_entry.start_time >= ? AND block_entry.start_time < ?
           ORDER BY block_entry.start_time""",
        (start_iso, end_iso),
    ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["start_time", "ip_address", "duration_s", "offence_count", "status", "expires_at", "released_at"]
    )
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_dashboard_csv_export.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/csv_export.py tests/unit/test_dashboard_csv_export.py
git commit -m "feat: add CSV export for alerts and blocks (FR-11.3)"
```

---

## Task 13: FastAPI app — routes and WebSocket push (`services/dashboard/api.py`)

**Files:**
- Create: `services/dashboard/api.py`
- Test: `tests/integration/test_dashboard_api.py`

**Interfaces:**
- Consumes: every module from Tasks 3-12, `common.db.migrate.connect` (Phase 1), `common.bus.
  EventBus` (Phase 1), FastAPI/Starlette.
- Produces: `create_app(conn, bus, session_store) -> FastAPI` (dependency-injected, so tests never
  touch a real file or Redis instance). Routes: `POST /api/login`, `POST /api/logout`,
  `GET /api/overview`, `GET /api/alerts`, `GET /api/alerts/{verdict_id}/evidence`,
  `GET /api/blocked-hosts`, `POST /api/blocked-hosts/{ip}/unblock`, `GET /api/allowlist`,
  `POST /api/allowlist`, `DELETE /api/allowlist/{entry_id}`, `GET /api/hosts`,
  `GET /api/settings/{tab}`, `PUT /api/settings/{key}`, `POST /api/admin/reload-rules`,
  `POST /api/admin/recalibrate`, `GET /api/health`, `GET /api/models`,
  `GET /api/export/alerts.csv`, `GET /api/export/blocks.csv`, `WS /ws/live`. Every route except
  `/api/login` requires a valid session cookie (FR-9.1 — "require the administrator to log in before
  the dashboard can be viewed").

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_dashboard_api.py
import fakeredis
from fastapi.testclient import TestClient

from common.bus import EventBus
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.dashboard.api import create_app
from services.dashboard.auth import create_admin_user
from services.dashboard.sessions import SessionStore


def _client():
    conn = connect(":memory:")
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    sessions = SessionStore(fakeredis.FakeRedis(decode_responses=True))
    app = create_app(conn, bus, sessions)
    return TestClient(app), conn


def test_protected_route_rejects_unauthenticated_request():
    client, _ = _client()

    response = client.get("/api/overview")

    assert response.status_code == 401


def test_login_with_wrong_password_returns_generic_error():
    client, _ = _client()

    response = client.post("/api/login", json={"username": "admin", "password": "wrong"})

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_credentials"


def test_login_then_overview_succeeds():
    client, _ = _client()

    login = client.post("/api/login", json={"username": "admin", "password": "correct-password"})
    assert login.status_code == 200

    overview = client.get("/api/overview")
    assert overview.status_code == 200
    body = overview.json()
    assert "flows_analyzed" in body
    assert "intrusions_detected" in body
    assert "active_blocks" in body


def test_logout_revokes_session():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    client.post("/api/logout")

    assert client.get("/api/overview").status_code == 401


def test_settings_tab_requires_auth_then_returns_rows():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.get("/api/settings/detection_layers")

    assert response.status_code == 200
    keys = {row["key"] for row in response.json()}
    assert "detection.layer1_enabled" in keys


def test_update_setting_then_read_back():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    put = client.put("/api/settings/risk.block_threshold", json={"value": 7.0})
    assert put.status_code == 200

    rows = client.get("/api/settings/thresholds").json()
    row = next(r for r in rows if r["key"] == "risk.block_threshold")
    assert row["value"] == 7.0


def test_allowlist_add_then_list():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    add = client.post("/api/allowlist", json={"address": "192.168.1.1", "description": "ISP gateway"})
    assert add.status_code == 200

    rows = client.get("/api/allowlist").json()
    assert any(r["address"] == "192.168.1.1" for r in rows)


def test_unblock_route_publishes_admin_command_without_error():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.post("/api/blocked-hosts/10.0.0.5/unblock")

    assert response.status_code == 202  # accepted -- see Global Constraints' admin-command contract


def test_export_alerts_csv_returns_csv_content_type():
    client, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.get(
        "/api/export/alerts.csv",
        params={"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")


def test_websocket_live_requires_valid_session_token():
    client, _ = _client()
    login = client.post("/api/login", json={"username": "admin", "password": "correct-password"})
    token = login.json()["token"]

    with client.websocket_connect(f"/ws/live?token={token}") as ws:
        message = ws.receive_json()
        assert "flows_analyzed" in message
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/integration/test_dashboard_api.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.dashboard.api'`

- [ ] **Step 3: Write `services/dashboard/api.py`**

```python
"""FastAPI app wiring every dashboard module into the routes the six screens call (FR-9, FR-10,
FR-11.3). create_app() takes its conn/bus/session_store as parameters rather than constructing
them itself, so every test here runs against an in-memory DB and fakeredis with no real network
or filesystem dependency."""
from __future__ import annotations

import sqlite3

from fastapi import Cookie, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from common.bus import EventBus
from services.dashboard import csv_export, queries
from services.dashboard.admin_commands import AdminCommands
from services.dashboard.auth import authenticate
from services.dashboard.config_api import get_tab, update_setting
from services.dashboard.live_stats import LiveStats
from services.dashboard.sessions import SessionStore

SESSION_COOKIE = "nidps_session"


class LoginRequest(BaseModel):
    username: str
    password: str


class SettingUpdate(BaseModel):
    value: object


class AllowlistCreate(BaseModel):
    address: str
    description: str = ""


def create_app(conn: sqlite3.Connection, bus: EventBus, session_store: SessionStore) -> FastAPI:
    app = FastAPI(title="NIDPS Dashboard API")
    live_stats = LiveStats(conn, bus)
    admin_commands = AdminCommands(bus)

    def _config_get(key: str):
        from common.config_loader import get as cfg_get
        return cfg_get(conn, key)

    def require_session(nidps_session: str | None = Cookie(default=None)) -> int:
        user_id = session_store.user_id_for(nidps_session) if nidps_session else None
        if user_id is None:
            raise HTTPException(status_code=401, detail="not_authenticated")
        return user_id

    @app.post("/api/login")
    def login(body: LoginRequest):
        from fastapi.responses import JSONResponse

        result = authenticate(conn, _config_get, body.username, body.password)
        if not result.ok:
            raise HTTPException(status_code=401, detail=result.reason)
        token = session_store.create(result.user_id)
        resp = JSONResponse({"ok": True, "token": token})
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return resp

    @app.post("/api/logout")
    def logout(nidps_session: str | None = Cookie(default=None)):
        if nidps_session:
            session_store.revoke(nidps_session)
        return {"ok": True}

    @app.get("/api/overview")
    def overview(user_id: int = require_session):
        return live_stats.snapshot()

    @app.get("/api/alerts")
    def alerts(
        host_ip: str | None = None, attack_class: str | None = None, limit: int = 50,
        user_id: int = require_session,
    ):
        return queries.list_alerts(conn, limit=limit, host_ip=host_ip, attack_class=attack_class)

    @app.get("/api/alerts/{verdict_id}/evidence")
    def evidence(verdict_id: int, user_id: int = require_session):
        return queries.alert_evidence(conn, verdict_id)

    @app.get("/api/blocked-hosts")
    def blocked_hosts(user_id: int = require_session):
        return queries.list_blocked_hosts(conn)

    @app.post("/api/blocked-hosts/{ip}/unblock", status_code=202)
    def unblock(ip: str, user_id: int = require_session):
        admin_commands.request_unblock(ip, requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.get("/api/allowlist")
    def allowlist(user_id: int = require_session):
        return queries.list_allowlist(conn)

    @app.post("/api/allowlist")
    def add_allowlist(body: AllowlistCreate, user_id: int = require_session):
        entry_id = queries.add_allowlist_entry(conn, body.address, body.description, added_by=user_id)
        return {"entry_id": entry_id}

    @app.delete("/api/allowlist/{entry_id}")
    def remove_allowlist(entry_id: int, user_id: int = require_session):
        queries.remove_allowlist_entry(conn, entry_id)
        return {"ok": True}

    @app.get("/api/hosts")
    def hosts(user_id: int = require_session):
        return queries.list_hosts(conn)

    @app.get("/api/settings/{tab}")
    def settings_tab(tab: str, user_id: int = require_session):
        try:
            return get_tab(conn, tab)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown_tab")

    @app.put("/api/settings/{key}")
    def settings_update(key: str, body: SettingUpdate, user_id: int = require_session):
        try:
            update_setting(conn, key, body.value, user_id=user_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"ok": True}

    @app.post("/api/admin/reload-rules", status_code=202)
    def reload_rules(user_id: int = require_session):
        admin_commands.request_reload_rules(requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.post("/api/admin/recalibrate", status_code=202)
    def recalibrate(user_id: int = require_session):
        admin_commands.request_recalibration(requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.get("/api/health")
    def health(user_id: int = require_session):
        return queries.component_health(conn)

    @app.get("/api/models")
    def models(user_id: int = require_session):
        return queries.list_models(conn)

    @app.get("/api/export/alerts.csv")
    def export_alerts(start: str = Query(...), end: str = Query(...), user_id: int = require_session):
        return PlainTextResponse(csv_export.export_alerts_csv(conn, start, end), media_type="text/csv")

    @app.get("/api/export/blocks.csv")
    def export_blocks(start: str = Query(...), end: str = Query(...), user_id: int = require_session):
        return PlainTextResponse(csv_export.export_blocks_csv(conn, start, end), media_type="text/csv")

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket, token: str = Query(...)):
        user_id = session_store.user_id_for(token)
        if user_id is None:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            await websocket.send_json(live_stats.snapshot())
            while True:
                await websocket.receive_text()  # keepalive ping from the client; ignored
                await websocket.send_json(live_stats.snapshot())
        except WebSocketDisconnect:
            pass

    return app
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/integration/test_dashboard_api.py -v`
Expected: 10 passed

Note on Step 1's websocket test: `TestClient.websocket_connect` sends no message before the server's
first `await websocket.receive_text()` call in some client versions, which would hang. The test as
written only calls `ws.receive_json()` once (for the immediate post-accept snapshot) and does not
wait on a second message, so it does not depend on the client sending anything — confirm this still
holds for the installed `starlette`/`httpx` versions; if the test client's `receive_json()` call
blocks instead of returning promptly, add `ws.send_text("ping")` before it is unnecessary for this
first assertion and should be removed rather than added.

- [ ] **Step 5: Commit**

```bash
git add services/dashboard/api.py tests/integration/test_dashboard_api.py
git commit -m "feat: add FastAPI dashboard app with session auth and WebSocket live push"
```

---

## Task 14: Entry point (`services/dashboard/main.py`)

**Files:**
- Create: `services/dashboard/main.py`

**Interfaces:**
- Consumes: every module from Tasks 1-13, `common.db.migrate.connect`, `common.bus.EventBus`,
  `common.logging_setup.configure_logging`, `common.schemas.{ComponentHealth, HealthState,
  utc_now_iso}` (Phase 1), `uvicorn`.
- Produces: a runnable service. `COMPONENT_NAME = "dashboard"` — matches the name Phase 5's
  watchdog plan already hardcodes in its `DEFAULT_UNIT_MAP` (`"dashboard": "nidps-dashboard.service"`)
  and its own test (`_beat(watchdog, name="dashboard")`), and the `deploy/nidps-dashboard.service`
  unit file Phase 5 already created with `ExecStart=/opt/nidps/.venv/bin/python -m
  services.dashboard.main` — **this plan does not recreate that systemd unit file; it already
  exists from Phase 5.**

- [ ] **Step 1: Write `services/dashboard/main.py`**

```python
"""Dashboard entry point. Runs the Event Store and live-stats consumers on background threads and
serves the FastAPI app via uvicorn in the foreground, publishing a heartbeat every
watchdog.heartbeat_interval_s so Phase 5's watchdog supervises this process exactly like every
other NIDPS service. COMPONENT_NAME matches the "dashboard" name already hardcoded in Phase 5's
DEFAULT_UNIT_MAP and deploy/nidps-dashboard.service (already created by that phase -- not
recreated here)."""
from __future__ import annotations

import os
import threading
import time

import uvicorn

from common.bus import STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, HealthState, utc_now_iso

from services.dashboard.api import create_app
from services.dashboard.event_store import EventStore
from services.dashboard.live_stats import LiveStats
from services.dashboard.sessions import SessionStore

COMPONENT_NAME = "dashboard"


def _run_consumer_loop(name: str, consume_once, stop_event: threading.Event) -> None:
    logger = configure_logging(f"{COMPONENT_NAME}.{name}")
    while not stop_event.is_set():
        try:
            consume_once(block_ms=1000)
        except Exception:
            logger.exception("consumer loop error")
            time.sleep(1.0)


def _heartbeat_loop(bus: EventBus, config_fn, stop_event: threading.Event) -> None:
    logger = configure_logging(COMPONENT_NAME)
    while not stop_event.is_set():
        interval = float(config_fn("watchdog.heartbeat_interval_s"))
        health = ComponentHealth(
            name=COMPONENT_NAME, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
        bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))
        logger.info('{"event": "heartbeat"}')
        time.sleep(interval)


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.db")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    host = os.environ.get("NIDPS_DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("NIDPS_DASHBOARD_PORT", "8443"))

    conn = connect(db_path)
    seed_defaults(conn)
    bus = EventBus.from_url(redis_url)
    session_store = SessionStore(bus._client, ttl_s=1800)

    event_store = EventStore(conn, bus)
    live_stats = LiveStats(conn, bus)
    stop_event = threading.Event()

    threads = [
        threading.Thread(
            target=_run_consumer_loop, args=("event-store", event_store.consume_once, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_run_consumer_loop, args=("live-stats", live_stats.consume_once, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_heartbeat_loop, args=(bus, lambda key: config_get(conn, key), stop_event),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    app = create_app(conn, bus, session_store)
    try:
        uvicorn.run(app, host=host, port=port, log_level="info")
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Manual smoke test (no automated test — this task only wires already-tested units)**

Run (with a local Redis listening on 6379):
```bash
NIDPS_DB_PATH=:memory:  # not valid for the real CLI (sqlite3 needs a real path or literal ":memory:" string, which is in fact accepted by sqlite3.connect) -- for a quick manual check use a throwaway file instead:
NIDPS_DB_PATH=./smoke.db NIDPS_DASHBOARD_PORT=8443 .venv/Scripts/python -m services.dashboard.main
```
Expected: process starts, logs `{"event": "heartbeat", ...}` once per `watchdog.heartbeat_interval_s`
(default 1.0s), and `curl http://localhost:8443/api/login -X POST -H "Content-Type: application/json"
-d "{\"username\":\"admin\",\"password\":\"x\"}"` returns `401` with `{"detail":"invalid_credentials"}`
(no admin user exists yet — expected, since Task 3's `create_admin.py` CLI is the seeding step,
documented as a separate operator action, not part of `main.py`'s own startup). Stop with Ctrl+C;
delete `./smoke.db` afterward.

- [ ] **Step 3: Commit**

```bash
git add services/dashboard/main.py
git commit -m "feat: add dashboard service entry point (Event Store + live stats + FastAPI + heartbeat)"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:** FR-9.1 → Tasks 3-5, 13 (login/lockout/generic-error, session auth on every
  route); FR-9.2 (≥2s refresh) → Task 13's WebSocket push + Task 8's in-memory counters (no DB query
  per refresh); FR-9.3/9.4 (alert list + evidence) → Task 11's `list_alerts`/`alert_evidence`;
  FR-9.5 (unblock) → Task 10/13 (documented admin-command gap — see Global Constraints); FR-9.6
  (host traffic/risk) → Task 11's `list_hosts`; FR-9.7 (component health) → Task 11's
  `component_health`; FR-10.1-10.3 (layer toggles, failure mode, thresholds within safe limits) →
  Task 9's grouped config API, which inherits `validate_value()`'s range checks from Phase 1
  unchanged; FR-10.4 (allowlist add/remove) → Task 11; FR-10.5 (reload rules / recalibrate on
  demand) → Task 10 (same documented gap); FR-10.6 (no-restart + audit log) → inherited unchanged
  from Phase 1's `common.config_loader.update()`, never re-implemented here; FR-11.1 (persist
  evidence/verdicts) → Task 7's Event Store; FR-11.3 (CSV export) → Task 12.
- **Placeholder scan:** none found — every step has complete code and literal expected output,
  except Task 14 Step 2, which is explicitly a manual smoke test (not a placeholder — `main.py`
  wires together modules every one of which already has full unit/integration coverage in Tasks
  1-13, so an automated test of `main()` itself would only re-test process bootstrapping, not logic).
- **Known, intentionally-scoped gaps (not defects — each is explained where it occurs):** the
  admin-command stream (unblock/reload-rules/recalibrate) has no consumer yet in the three
  already-written, sealed phases it targets — Global Constraints' "Admin-command bus contract" and
  Sprint 10 of the master roadmap are where this closes. The Settings screen's Models tab is
  read-only by design (UC-12's actor is the Model Maintainer's CLI, not this dashboard's admin
  login) — Global Constraints' "Settings screen UC-12 scope note."
- **Type/contract consistency:** `EventStore` and `Enforcer` (Phase 4) derive the same `verdict_id`
  from the same `message_id` via byte-for-byte identical functions (Task 6), so their respective
  `INSERT OR IGNORE` writes for a BLOCK verdict converge exactly as Phase 4's plan requires.
  `SETTINGS_TABS` in Task 9 is exhaustively checked (via `test_every_config_key_is_assigned_to_
  exactly_one_tab`) against `common.config_schema.CONFIG_KEYS_BY_NAME`, so Phase 1 adding a new
  config key without updating this plan's grouping fails a test rather than silently going
  unreachable from the Settings screen.
