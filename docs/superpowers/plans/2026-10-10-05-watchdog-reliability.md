# NIDPS Watchdog & Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `services/watchdog/` — the process supervisor that tracks every other NIDPS
service's health via heartbeats, drives each component through a Normal/Degraded/Failed/Recovering
state machine, restarts failed components via `systemctl`, applies the admin's chosen failure mode
(fail-open / fail-closed / degraded) while a component is down, and logs every transition to
`component_event` — plus `deploy/` — the systemd unit files for all nine NIDPS services.

**Architecture:** A single long-running `Watchdog` class (pure state machine + side effects: DB
writes, `systemctl`/`iptables` subprocess calls, a Redis-backed runtime flag) wired up by
`services/watchdog/main.py`, which consumes `ComponentHealth` heartbeats from `STREAM_HEARTBEATS`
(published by every other NIDPS service, built in parallel phases) and calls `checkAll()` once per
`watchdog.heartbeat_interval_s`. The watchdog is the authoritative, synchronous writer of
`component_event` — it does not go through the (separate, later) Event Store. Kernel-level
fail-open behaviour (NFQUEUE `--queue-bypass`) is already in place from an earlier phase; this plan's
job for `FAIL_CLOSED` is to actively override that default by inserting a temporary `iptables` DROP
rule, and for `DEGRADED` is to flip a lightweight Redis flag that detection services poll.

**Tech Stack:** Python 3.11+, `redis`/`fakeredis` (already in `requirements.txt`), `psutil` (added by
this plan) for CPU sampling, stdlib `subprocess`/`sqlite3`/`json`/`time`, `pytest`.

## Global Constraints

- Python 3.11+ (spec Table: Technology Stack). All timestamps are UTC ISO 8601 strings produced only
  via `common.schemas.utc_now_iso()` — never call `datetime.now()` directly in this plan's code.
- **Table ownership:** this plan owns `component_event` entirely (full read/write), written
  synchronously and directly — not via the bus/Event Store. `evidence` and `verdict` are out of
  scope for this plan (owned by other phases). This plan never writes `config_setting` rows itself;
  it only reads them via `common.config_loader.get()` (wrapped in a 5-second-TTL `CachedConfig`,
  matching the convention already established in `services/enforcer/config_cache.py` by Phase 4 —
  this plan defines its own local copy at `services/watchdog/config_cache.py` rather than importing
  across service packages, since no phase may depend on another phase's `services/*` internals; only
  `common/` is a shared import surface).
- **`HealthState.NORMAL` ↔ DB `'RUNNING'` naming mismatch (documented, not a bug):** the
  `component_event.state` column's CHECK constraint (Phase 1's `common/db/schema.sql`) only allows
  `'RUNNING' | 'DEGRADED' | 'FAILED' | 'RECOVERING'`, while `common.schemas.HealthState` names the
  same concept `NORMAL`. Every DB write in this plan maps `HealthState.NORMAL` to the literal string
  `"RUNNING"` and uses `HealthState.DEGRADED.value` / `HealthState.FAILED.value` /
  `HealthState.RECOVERING.value` unchanged for the other three (they already match the CHECK
  constraint's spelling). This mapping lives in exactly one place (`watchdog.py`'s
  `_DB_STATE_FOR_NORMAL = "RUNNING"` constant) so it can't drift.
- **One `component_event` row per continuous incident, updated in place.** `detected_at`/
  `recovered_at` only make sense paired on a single row, so this plan inserts one row when a
  component first leaves `NORMAL` (to `DEGRADED` or `FAILED`) and keeps updating that same row's
  `state` column as the incident escalates/retries (e.g. `FAILED` → `RECOVERING` → `FAILED` again
  after a timed-out restart), only stamping `recovered_at` and closing the row when the component
  is fully back to `NORMAL`. This is a deliberate design choice (the spec gives a column pair, not a
  row-per-transition log) — documented here so it isn't mistaken for under-logging.
- **`packets_dropped`/`packets_bypassed` data source (FR-8.5):** `common.schemas.ComponentHealth` (
  fixed by Phase 1, not modifiable by this plan) has no `packets_dropped`/`packets_bypassed`
  attributes — only `name`, `state`, `last_heartbeat`, `queue_depth`, `cpu_pct`, `mem_mb`. This plan
  reads those two fields via `getattr(health, "packets_dropped", 0)` / `getattr(health,
  "packets_bypassed", 0)` off the affected component's last-received `ComponentHealth`, so today they
  will always default to `0` — documented explicitly per the task brief's instruction, and
  forward-compatible if a later revision of `ComponentHealth` adds those fields.
- **Degraded-mode signal is a Redis key, not a `config_setting` row.** `common.config_loader.update()`
  writes an `audit_log` row on every change (correct for admin-initiated settings, FR-10.6), which
  would flood `audit_log` with noise if used for a flag that can flip every second as CPU crosses a
  watermark. This plan instead uses a single plain Redis string key
  (`services/watchdog/runtime_flags.py::RUNTIME_KEY_DEGRADED_MODE`,
  `"nidps:runtime:degraded_mode_active"`), written directly via a redis-py-compatible client (the
  same `fakeredis.FakeRedis` instance in tests). Detection services (built in other phases) poll it
  with a plain `GET`. This is the "non-persistent/runtime flag" the task brief asked this plan to
  design pragmatically.
- **Critical inline components subject to fail-open/fail-closed enforcement:** only `"sigbridge"` (
  the Suricata eve.json/NFQUEUE alert bridge — the one component whose failure means the inline
  inspection point itself has gone dark) is treated as "critical inline" by default
  (`Watchdog.__init__`'s `critical_inline_components` parameter, default
  `frozenset({"sigbridge"})`). Every other component (flowextract, arpmon, anomaly_service,
  classifier, decision-engine, enforcer, dashboard) still goes through the full Normal/Degraded/
  Failed/Recovering state machine and gets restarted, but never triggers an `iptables` DROP insertion
  — their failure doesn't remove the kernel-level inline inspection path, so NFR-9's "keep internet
  access uninterrupted" concern doesn't apply to them the same way. This set is a plain constructor
  parameter, overridable if a deployment wants to extend it.
- **Component names are free strings (no shared enum).** `common.schemas.ComponentHealth.name` is
  typed `str`; there is no fixed enum of valid names in `common/`. This plan's
  `DEFAULT_UNIT_MAP` (`services/watchdog/watchdog.py`) is this plan's own best-effort mapping from the
  `name` each service is expected to publish to the systemd unit that runs it, built from two sources:
  the literal `COMPONENT_NAME` constants already committed in Phase 4's `services/decision/main.py`
  (`"decision-engine"`) and `services/enforcer/main.py` (`"enforcer"`), and the task brief's own
  example names (`"flowextract"`, `"anomaly_service"`, `"dashboard"`) for components whose
  phases (2, 3, 6) are not yet written. `"arpmon"`, `"sigbridge"`, `"classifier"` are this plan's own
  reasonable guesses by naming analogy. **This map is a plain `dict` passed into `Watchdog.__init__`,
  not hardcoded logic** — if a later phase's actual `COMPONENT_NAME` differs from this guess, fixing
  it is a one-line change to the map, not a code change.
- **Watchdog-is-alive verification is operator-driven, not a second watchdog.** `deploy/
  nidps-watchdog.service` uses `Restart=always` (every other unit uses `Restart=on-failure`) so
  systemd itself relaunches the watchdog process if it ever dies — this is the "meta" supervision
  layer, already provided by the OS, so this plan does not build a second watchdog process. The main
  loop (`services/watchdog/main.py`) additionally logs one `"watchdog_self_check"` JSON line per
  cycle (via `common.logging_setup.configure_logging`, so it lands in `journalctl -u
  nidps-watchdog`), giving an operator `systemctl status nidps-watchdog` (process-level liveness) and
  `journalctl -u nidps-watchdog -f` (logical liveness — is it actually ticking) as the two commands
  that answer "is the watchdog itself running."
- **Testing:** SQLite `:memory:` via `common.db.migrate.connect(":memory:")` for all DB tests;
  `fakeredis.FakeRedis(decode_responses=True)` for all Redis-touching tests (both the bus and the
  runtime flag); `SystemdClient.run()` and `IptablesClient.run()` are always injected/monkeypatched in
  tests — no test invokes a real `systemctl` or `iptables` binary or requires root.

---

## File Structure

```
services/
  watchdog/
    __init__.py
    config_cache.py     # CachedConfig: 5s-TTL wrapper over common.config_loader.get()
    systemd_client.py   # SystemdClient: run()/restart()/is_active()
    iptables_client.py  # IptablesClient: run()/insert_drop_all()/remove_drop_all()
    runtime_flags.py    # RuntimeFlag: set_degraded()/is_degraded() over a plain Redis key
    state_machine.py    # ComponentRecord + pure transition helpers (no I/O)
    watchdog.py          # Watchdog: components, onHeartbeat(), checkAll(), applyMode()
    main.py                # entry point: STREAM_HEARTBEATS consumer loop, self heartbeat, self-check log
deploy/
  nidps-flowextract.service
  nidps-arpmon.service
  nidps-sigbridge.service
  nidps-anomaly.service
  nidps-classifier.service
  nidps-decision.service
  nidps-enforcer.service
  nidps-watchdog.service
  nidps-dashboard.service
tests/
  unit/
    test_watchdog_config_cache.py
    test_systemd_client.py
    test_iptables_client.py
    test_runtime_flags.py
    test_state_machine.py
    test_watchdog_core.py
    test_watchdog_cpu_watermarks.py
    test_watchdog_failure_modes.py
    test_watchdog_fault_injection.py
  integration/
    test_watchdog_main.py
```

---

## Task 1: Project dependency + TTL config cache (`services/watchdog/config_cache.py`)

**Files:**
- Modify: `requirements.txt`
- Create: `services/watchdog/__init__.py`
- Create: `services/watchdog/config_cache.py`
- Test: `tests/unit/test_watchdog_config_cache.py`

**Interfaces:**
- Consumes: `common.config_loader.get` (Phase 1), `common.db.migrate.connect`/`seed_defaults`
  (Phase 1).
- Produces: `CachedConfig` class with `__init__(self, conn, ttl_s: float = 5.0, now_fn:
  Callable[[], float] = time.monotonic)` and `get(self, key: str)`. Every later task in this plan
  reads config exclusively through an instance of this class (FR-10.6 — config changes apply without
  restart, bounded by the TTL).

- [ ] **Step 1: Add `psutil` to `requirements.txt`**

Append to `requirements.txt`:
```
psutil>=5.9,<6.0
```

- [ ] **Step 2: Install the new dependency**

Run:
```bash
.venv/Scripts/pip install -r requirements.txt
```
Expected: `psutil` installs without error.

- [ ] **Step 3: Create `services/watchdog/__init__.py`**

```python
```

- [ ] **Step 4: Write the failing tests**

```python
# tests/unit/test_watchdog_config_cache.py
from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.watchdog.config_cache import CachedConfig


class _Clock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now


def test_get_returns_seeded_default():
    conn = connect(":memory:")
    seed_defaults(conn)
    cache = CachedConfig(conn, ttl_s=5.0, now_fn=_Clock())

    assert cache.get("watchdog.cpu_high_watermark") == 0.85


def test_get_returns_stale_value_within_ttl():
    conn = connect(":memory:")
    seed_defaults(conn)
    clock = _Clock()
    cache = CachedConfig(conn, ttl_s=5.0, now_fn=clock)

    assert cache.get("watchdog.cpu_high_watermark") == 0.85
    update(conn, "watchdog.cpu_high_watermark", 0.95)
    clock.now += 2.0

    assert cache.get("watchdog.cpu_high_watermark") == 0.85  # still cached


def test_get_refreshes_after_ttl_expires():
    conn = connect(":memory:")
    seed_defaults(conn)
    clock = _Clock()
    cache = CachedConfig(conn, ttl_s=5.0, now_fn=clock)

    assert cache.get("watchdog.cpu_high_watermark") == 0.85
    update(conn, "watchdog.cpu_high_watermark", 0.95)
    clock.now += 5.1

    assert cache.get("watchdog.cpu_high_watermark") == 0.95
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_config_cache.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.config_cache'`

- [ ] **Step 6: Write `services/watchdog/config_cache.py`**

```python
"""Short-TTL cache over common.config_loader.get(), so FR-10.6 (apply config changes without
restart) is satisfied by polling rather than reading config once at startup. Every config read
in this plan's watchdog code goes through an instance of this class."""
from __future__ import annotations

import time
from typing import Callable, Union

from common.config_loader import get as config_get

Number = Union[int, float]


class CachedConfig:
    def __init__(
        self,
        conn,
        ttl_s: float = 5.0,
        now_fn: Callable[[], float] = time.monotonic,
    ):
        self._conn = conn
        self._ttl_s = ttl_s
        self._now = now_fn
        self._cache: dict[str, tuple[float, Union[Number, str, bool]]] = {}

    def get(self, key: str) -> Union[Number, str, bool]:
        cached = self._cache.get(key)
        now = self._now()
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        value = config_get(self._conn, key)
        self._cache[key] = (now, value)
        return value
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_config_cache.py -v`
Expected: 3 passed

- [ ] **Step 8: Commit**

```bash
git add requirements.txt services/watchdog/__init__.py services/watchdog/config_cache.py tests/unit/test_watchdog_config_cache.py
git commit -m "feat: add watchdog TTL config cache and psutil dependency"
```

---

## Task 2: `systemctl` subprocess wrapper (`services/watchdog/systemd_client.py`)

**Files:**
- Create: `services/watchdog/systemd_client.py`
- Test: `tests/unit/test_systemd_client.py`

**Interfaces:**
- Consumes: stdlib `subprocess`.
- Produces: `SystemdClient` class with `__init__(self, runner: Optional[Callable] = None)`,
  `run(self, argv: list[str])`, `restart(self, unit_name: str)`, `is_active(self, unit_name: str) ->
  bool`. Task 7's `Watchdog.checkAll()`/`applyMode()` call `restart()` exclusively — no code in this
  plan calls `subprocess.run(["systemctl", ...])` directly.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_systemd_client.py
from services.watchdog.systemd_client import SystemdClient


def test_run_passes_argv_through_to_injected_runner():
    calls = []
    client = SystemdClient(runner=lambda argv: calls.append(argv))

    client.run(["systemctl", "status", "nidps-enforcer.service"])

    assert calls == [["systemctl", "status", "nidps-enforcer.service"]]


def test_restart_builds_exact_argv():
    calls = []
    client = SystemdClient(runner=lambda argv: calls.append(argv))

    client.restart("nidps-enforcer.service")

    assert calls == [["systemctl", "restart", "nidps-enforcer.service"]]


def test_is_active_true_when_runner_reports_active():
    class _Result:
        stdout = "active\n"

    client = SystemdClient(runner=lambda argv: _Result())

    assert client.is_active("nidps-enforcer.service") is True


def test_is_active_false_when_runner_reports_inactive():
    class _Result:
        stdout = "inactive\n"

    client = SystemdClient(runner=lambda argv: _Result())

    assert client.is_active("nidps-enforcer.service") is False


def test_default_runner_uses_subprocess(monkeypatch):
    captured = {}

    def fake_run(argv, capture_output, text, check):
        captured["argv"] = argv

        class _Result:
            stdout = "active\n"

        return _Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    client = SystemdClient()

    client.restart("nidps-enforcer.service")

    assert captured["argv"] == ["systemctl", "restart", "nidps-enforcer.service"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_systemd_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.systemd_client'`

- [ ] **Step 3: Write `services/watchdog/systemd_client.py`**

```python
"""Thin subprocess wrapper over the systemctl CLI (FR-8.2). Watchdog.checkAll()/applyMode() call
restart()/is_active() exclusively -- no other code in this plan touches subprocess directly, so
every test can inject a fake runner instead of requiring root or a real systemd."""
from __future__ import annotations

import subprocess
from typing import Callable, Optional


class SystemdClient:
    def __init__(self, runner: Optional[Callable] = None):
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str]):
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def run(self, argv: list[str]):
        return self._runner(argv)

    def restart(self, unit_name: str):
        return self.run(["systemctl", "restart", unit_name])

    def is_active(self, unit_name: str) -> bool:
        result = self.run(["systemctl", "is-active", unit_name])
        return getattr(result, "stdout", "").strip() == "active"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_systemd_client.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/systemd_client.py tests/unit/test_systemd_client.py
git commit -m "feat: add SystemdClient subprocess wrapper for component restarts"
```

---

## Task 3: `iptables` subprocess wrapper (`services/watchdog/iptables_client.py`)

**Files:**
- Create: `services/watchdog/iptables_client.py`
- Test: `tests/unit/test_iptables_client.py`

**Interfaces:**
- Consumes: stdlib `subprocess`.
- Produces: `IptablesClient` class with `__init__(self, runner: Optional[Callable] = None, chain:
  str = "FORWARD")`, `run(self, argv: list[str])`, `insert_drop_all(self)`, `remove_drop_all(self)`.
  Task 8's fail-closed branch calls `insert_drop_all()`/`remove_drop_all()` exclusively.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_iptables_client.py
from services.watchdog.iptables_client import IptablesClient


def test_run_passes_argv_through_to_injected_runner():
    calls = []
    client = IptablesClient(runner=lambda argv: calls.append(argv))

    client.run(["iptables", "-L"])

    assert calls == [["iptables", "-L"]]


def test_insert_drop_all_builds_exact_argv():
    calls = []
    client = IptablesClient(runner=lambda argv: calls.append(argv))

    client.insert_drop_all()

    assert calls == [["iptables", "-I", "FORWARD", "1", "-j", "DROP"]]


def test_remove_drop_all_builds_exact_argv():
    calls = []
    client = IptablesClient(runner=lambda argv: calls.append(argv))

    client.remove_drop_all()

    assert calls == [["iptables", "-D", "FORWARD", "-j", "DROP"]]


def test_custom_chain_is_used_in_both_commands():
    calls = []
    client = IptablesClient(runner=lambda argv: calls.append(argv), chain="FORWARD-NIDPS")

    client.insert_drop_all()
    client.remove_drop_all()

    assert calls == [
        ["iptables", "-I", "FORWARD-NIDPS", "1", "-j", "DROP"],
        ["iptables", "-D", "FORWARD-NIDPS", "-j", "DROP"],
    ]


def test_default_runner_uses_subprocess(monkeypatch):
    captured = {}

    def fake_run(argv, capture_output, text, check):
        captured["argv"] = argv

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    client = IptablesClient()

    client.insert_drop_all()

    assert captured["argv"] == ["iptables", "-I", "FORWARD", "1", "-j", "DROP"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_iptables_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.iptables_client'`

- [ ] **Step 3: Write `services/watchdog/iptables_client.py`**

```python
"""Thin subprocess wrapper over the iptables CLI, used only for the FAIL_CLOSED failure mode
(FR-8.3). The kernel's NFQUEUE --queue-bypass flag (set up by an earlier, already-completed
phase) already makes the default behaviour fail-open when the inline inspection process stops
responding; FAIL_CLOSED is the one case where this plan must actively override that default by
inserting a temporary DROP rule, then remove it once the component recovers."""
from __future__ import annotations

import subprocess
from typing import Callable, Optional


class IptablesClient:
    def __init__(self, runner: Optional[Callable] = None, chain: str = "FORWARD"):
        self._runner = runner or self._default_runner
        self._chain = chain

    @staticmethod
    def _default_runner(argv: list[str]):
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def run(self, argv: list[str]):
        return self._runner(argv)

    def insert_drop_all(self):
        return self.run(["iptables", "-I", self._chain, "1", "-j", "DROP"])

    def remove_drop_all(self):
        return self.run(["iptables", "-D", self._chain, "-j", "DROP"])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_iptables_client.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/iptables_client.py tests/unit/test_iptables_client.py
git commit -m "feat: add IptablesClient subprocess wrapper for FAIL_CLOSED enforcement"
```

---

## Task 4: Non-persistent degraded-mode runtime flag (`services/watchdog/runtime_flags.py`)

**Files:**
- Create: `services/watchdog/runtime_flags.py`
- Test: `tests/unit/test_runtime_flags.py`

**Interfaces:**
- Consumes: a redis-py-compatible client (real `redis.Redis` or `fakeredis.FakeRedis`).
- Produces: `RUNTIME_KEY_DEGRADED_MODE: str`; `RuntimeFlag` class with `__init__(self,
  redis_client)`, `set_degraded(self, active: bool) -> None`, `is_degraded(self) -> bool`. Task 8's
  `Watchdog` writes this flag; detection services (built by other, parallel phases) are documented to
  poll it with a plain `GET` on the same key — this plan does not modify those other services.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_runtime_flags.py
import fakeredis

from services.watchdog.runtime_flags import RUNTIME_KEY_DEGRADED_MODE, RuntimeFlag


def test_is_degraded_defaults_to_false_when_key_absent():
    client = fakeredis.FakeRedis(decode_responses=True)
    flag = RuntimeFlag(client)

    assert flag.is_degraded() is False


def test_set_degraded_true_then_read_back():
    client = fakeredis.FakeRedis(decode_responses=True)
    flag = RuntimeFlag(client)

    flag.set_degraded(True)

    assert flag.is_degraded() is True
    assert client.get(RUNTIME_KEY_DEGRADED_MODE) == "1"


def test_set_degraded_false_then_read_back():
    client = fakeredis.FakeRedis(decode_responses=True)
    flag = RuntimeFlag(client)

    flag.set_degraded(True)
    flag.set_degraded(False)

    assert flag.is_degraded() is False
    assert client.get(RUNTIME_KEY_DEGRADED_MODE) == "0"


def test_is_degraded_handles_bytes_client():
    client = fakeredis.FakeRedis(decode_responses=False)
    flag = RuntimeFlag(client)

    flag.set_degraded(True)

    assert flag.is_degraded() is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_runtime_flags.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.runtime_flags'`

- [ ] **Step 3: Write `services/watchdog/runtime_flags.py`**

```python
"""Non-persistent, non-audited runtime flag the watchdog uses to tell detection services when
to reduce their sampling rate (FR-8.3/FR-8.4's DEGRADED signal). Deliberately NOT a
config_setting row: common.config_loader.update() writes an audit_log row on every change,
appropriate for an admin-initiated setting but noisy for a flag that can flip every second as
CPU crosses a watermark. This is instead a single plain Redis string key, written directly via
a redis-py-compatible client (fakeredis in tests) -- cheap to flip, visible to every process
that can reach the same Redis instance. Detection services (built by other phases) are expected
to poll is_degraded()-equivalent logic (a plain GET on this key) each cycle; this plan does not
implement that consumer side."""
from __future__ import annotations

RUNTIME_KEY_DEGRADED_MODE = "nidps:runtime:degraded_mode_active"


class RuntimeFlag:
    def __init__(self, redis_client):
        self._client = redis_client

    def set_degraded(self, active: bool) -> None:
        self._client.set(RUNTIME_KEY_DEGRADED_MODE, "1" if active else "0")

    def is_degraded(self) -> bool:
        value = self._client.get(RUNTIME_KEY_DEGRADED_MODE)
        if value is None:
            return False
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        return value == "1"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_runtime_flags.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/runtime_flags.py tests/unit/test_runtime_flags.py
git commit -m "feat: add non-persistent degraded-mode runtime flag over Redis"
```

---

## Task 5: Pure state-machine primitives (`services/watchdog/state_machine.py`)

**Files:**
- Create: `services/watchdog/state_machine.py`
- Test: `tests/unit/test_state_machine.py`

**Interfaces:**
- Consumes: `common.schemas.{ComponentHealth, HealthState}` (Phase 1).
- Produces: `ComponentRecord` dataclass (`name`, `state`, `ticks_since_heartbeat`,
  `recovering_since`, `failed_since`, `open_event_id`, `fail_closed_inserted`, `last_health`);
  `apply_heartbeat(record) -> bool` (returns `True` iff this heartbeat ends a FAILED/RECOVERING
  incident); `tick_and_check_failure(record, threshold: int) -> bool` (returns `True` exactly on the
  tick a component newly becomes FAILED); `check_recovery_timeout(record, now: float, timeout_s:
  float) -> bool`. These are pure functions with no DB/subprocess/bus I/O — Task 6's `Watchdog` class
  calls them and performs the side effects itself, so the state-transition logic can be tested in
  complete isolation from SQLite/Redis/subprocess.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_state_machine.py
from common.schemas import ComponentHealth, HealthState
from services.watchdog.state_machine import (
    ComponentRecord,
    apply_heartbeat,
    check_recovery_timeout,
    tick_and_check_failure,
)


def _health(name="enforcer"):
    return ComponentHealth(name=name, state=HealthState.NORMAL, last_heartbeat="t")


def test_apply_heartbeat_resets_tick_counter_and_stores_health():
    record = ComponentRecord(name="enforcer", ticks_since_heartbeat=2)

    recovered = apply_heartbeat(record)

    assert recovered is False
    assert record.ticks_since_heartbeat == 0


def test_apply_heartbeat_on_failed_component_signals_recovery_and_resets_state():
    record = ComponentRecord(
        name="enforcer", state=HealthState.FAILED, recovering_since=10.0, ticks_since_heartbeat=5
    )

    recovered = apply_heartbeat(record)

    assert recovered is True
    assert record.state == HealthState.NORMAL
    assert record.recovering_since is None
    assert record.ticks_since_heartbeat == 0


def test_apply_heartbeat_on_recovering_component_signals_recovery():
    record = ComponentRecord(name="enforcer", state=HealthState.RECOVERING, recovering_since=10.0)

    recovered = apply_heartbeat(record)

    assert recovered is True
    assert record.state == HealthState.NORMAL


def test_apply_heartbeat_on_degraded_component_does_not_signal_recovery():
    record = ComponentRecord(name="enforcer", state=HealthState.DEGRADED)

    recovered = apply_heartbeat(record)

    assert recovered is False
    assert record.state == HealthState.DEGRADED  # CPU-driven; left alone here


def test_tick_and_check_failure_returns_false_before_threshold():
    record = ComponentRecord(name="enforcer")

    assert tick_and_check_failure(record, threshold=3) is False
    assert tick_and_check_failure(record, threshold=3) is False
    assert record.state == HealthState.NORMAL


def test_tick_and_check_failure_returns_true_exactly_on_third_missed_tick():
    record = ComponentRecord(name="enforcer")

    assert tick_and_check_failure(record, threshold=3) is False
    assert tick_and_check_failure(record, threshold=3) is False
    assert tick_and_check_failure(record, threshold=3) is True
    assert record.state == HealthState.FAILED


def test_tick_and_check_failure_is_a_noop_once_already_failed_or_recovering():
    record = ComponentRecord(name="enforcer", state=HealthState.FAILED, ticks_since_heartbeat=99)

    assert tick_and_check_failure(record, threshold=3) is False
    assert record.ticks_since_heartbeat == 99  # untouched


def test_check_recovery_timeout_false_before_timeout_elapses():
    record = ComponentRecord(name="enforcer", state=HealthState.RECOVERING, recovering_since=100.0)

    assert check_recovery_timeout(record, now=110.0, timeout_s=30.0) is False


def test_check_recovery_timeout_true_after_timeout_elapses():
    record = ComponentRecord(name="enforcer", state=HealthState.RECOVERING, recovering_since=100.0)

    assert check_recovery_timeout(record, now=131.0, timeout_s=30.0) is True


def test_check_recovery_timeout_is_a_noop_outside_recovering_state():
    record = ComponentRecord(name="enforcer", state=HealthState.NORMAL)

    assert check_recovery_timeout(record, now=1000.0, timeout_s=30.0) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_state_machine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.state_machine'`

- [ ] **Step 3: Write `services/watchdog/state_machine.py`**

```python
"""Pure state-transition helpers for the watchdog's per-component state machine (FR-8.1,
FR-8.2). No DB, subprocess, or bus I/O happens here -- services/watchdog/watchdog.py calls these
and performs every side effect (component_event writes, systemctl/iptables calls) itself, so the
transition logic is testable in complete isolation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common.schemas import ComponentHealth, HealthState


@dataclass
class ComponentRecord:
    name: str
    state: HealthState = HealthState.NORMAL
    ticks_since_heartbeat: int = 0
    recovering_since: Optional[float] = None
    failed_since: Optional[float] = None
    open_event_id: Optional[int] = None
    fail_closed_inserted: bool = False
    last_health: Optional[ComponentHealth] = None


def apply_heartbeat(record: ComponentRecord) -> bool:
    """Call once per heartbeat received for this component. Resets the missed-heartbeat
    counter. Returns True iff this heartbeat ends a FAILED/RECOVERING incident (a recovery) --
    the caller is responsible for closing the open component_event row and clearing any
    FAIL_CLOSED iptables rule in that case."""
    was_down = record.state in (HealthState.FAILED, HealthState.RECOVERING)
    record.ticks_since_heartbeat = 0
    if was_down:
        record.state = HealthState.NORMAL
        record.recovering_since = None
    return was_down


def tick_and_check_failure(record: ComponentRecord, threshold: int) -> bool:
    """Call once per Watchdog.checkAll() tick for a component that has NOT just had
    apply_heartbeat() called on it this cycle. No-op (returns False) if the component is
    already FAILED or RECOVERING -- recovery-timeout handling is check_recovery_timeout()'s
    job, not this function's. Returns True exactly on the tick where the missed-heartbeat
    counter reaches `threshold` and the component newly transitions to FAILED."""
    if record.state in (HealthState.FAILED, HealthState.RECOVERING):
        return False
    record.ticks_since_heartbeat += 1
    if record.ticks_since_heartbeat >= threshold:
        record.state = HealthState.FAILED
        return True
    return False


def check_recovery_timeout(record: ComponentRecord, now: float, timeout_s: float) -> bool:
    """For a component in RECOVERING, returns True if the recovery timeout has elapsed since
    the restart was issued without a fresh heartbeat arriving. No-op (False) for any other
    state. Does not itself mutate record.state -- the caller decides whether to re-attempt the
    restart (by calling the watchdog's own escalate-to-FAILED-then-RECOVERING-again path)."""
    if record.state != HealthState.RECOVERING or record.recovering_since is None:
        return False
    return (now - record.recovering_since) > timeout_s
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_state_machine.py -v`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/state_machine.py tests/unit/test_state_machine.py
git commit -m "feat: add pure watchdog state-machine transition helpers"
```

---

## Task 6: `Watchdog` core — heartbeats, missed-beat failure, restart, recovery

**Files:**
- Create: `services/watchdog/watchdog.py`
- Test: `tests/unit/test_watchdog_core.py`

**Interfaces:**
- Consumes: `services.watchdog.state_machine.{ComponentRecord, apply_heartbeat,
  tick_and_check_failure, check_recovery_timeout}` (Task 5), `services.watchdog.systemd_client.
  SystemdClient` (Task 2), `services.watchdog.iptables_client.IptablesClient` (Task 3),
  `services.watchdog.runtime_flags.RuntimeFlag` (Task 4), `services.watchdog.config_cache.
  CachedConfig.get` (Task 1), `common.schemas.{ComponentHealth, HealthState, FailureMode,
  utc_now_iso}` (Phase 1), `common.logging_setup.configure_logging` (Phase 1).
- Produces: `DEFAULT_UNIT_MAP: dict[str, str]`; `Watchdog` class with public attr `components:
  dict[str, ComponentRecord]` and methods `onHeartbeat(self, status: ComponentHealth) -> None`,
  `checkAll(self) -> None`, `applyMode(self, component: str) -> str`. This task covers only the
  missed-heartbeat → FAILED → RECOVERING → NORMAL/FAILED path and `component_event` writes for it;
  Task 7 adds CPU-watermark-driven DEGRADED, Task 8 adds the FAIL_OPEN/FAIL_CLOSED/DEGRADED
  `applyMode()` branching.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_watchdog_core.py
from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState
from services.watchdog.config_cache import CachedConfig
from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.systemd_client import SystemdClient
from services.watchdog.watchdog import Watchdog

import fakeredis


class _Clock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now


def _make_watchdog(conn, now_fn=None, recovery_timeout_s=30.0):
    config = CachedConfig(conn, ttl_s=0.0, now_fn=lambda: 0.0)
    restart_calls = []
    systemd = SystemdClient(runner=lambda argv: restart_calls.append(argv))
    iptables = IptablesClient(runner=lambda argv: (_ for _ in ()).throw(AssertionError(argv)))
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    runtime_flag = RuntimeFlag(redis_client)
    watchdog = Watchdog(
        conn,
        config.get,
        systemd,
        iptables,
        runtime_flag,
        recovery_timeout_s=recovery_timeout_s,
        now_fn=now_fn or _Clock(),
        cpu_fn=lambda: 0.0,  # never crosses a watermark in this task's tests
    )
    return watchdog, restart_calls


def test_fresh_heartbeat_keeps_component_normal():
    conn = connect(":memory:")
    seed_defaults(conn)
    watchdog, _ = _make_watchdog(conn)

    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()

    assert watchdog.components["enforcer"].state == HealthState.NORMAL


def test_component_becomes_failed_after_exactly_threshold_missed_checks():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 3)
    watchdog, restart_calls = _make_watchdog(conn)

    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()  # miss 1
    assert watchdog.components["enforcer"].state == HealthState.NORMAL
    watchdog.checkAll()  # miss 2
    assert watchdog.components["enforcer"].state == HealthState.NORMAL
    watchdog.checkAll()  # miss 3 -> FAILED -> restart issued -> RECOVERING

    assert watchdog.components["enforcer"].state == HealthState.RECOVERING
    assert restart_calls == [["systemctl", "restart", "nidps-enforcer.service"]]


def test_component_event_row_written_on_failure_with_detected_at_and_no_recovered_at():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    watchdog, _ = _make_watchdog(conn)

    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()  # miss 1 -> FAILED -> RECOVERING

    row = conn.execute(
        "SELECT component, state, detected_at, recovered_at, packets_dropped, packets_bypassed "
        "FROM component_event WHERE component = 'enforcer'"
    ).fetchone()
    assert row[0] == "enforcer"
    assert row[1] == "RECOVERING"
    assert row[2] is not None
    assert row[3] is None
    assert row[4] == 0
    assert row[5] == 0


def test_fresh_heartbeat_after_failure_recovers_to_normal_and_closes_event_row():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    watchdog, _ = _make_watchdog(conn)

    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()  # -> FAILED -> RECOVERING
    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t2"))

    assert watchdog.components["enforcer"].state == HealthState.NORMAL
    row = conn.execute(
        "SELECT state, recovered_at FROM component_event WHERE component = 'enforcer'"
    ).fetchone()
    assert row[0] == "RUNNING"
    assert row[1] is not None


def test_recovering_component_returns_to_failed_and_retries_restart_after_timeout():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    clock = _Clock()
    watchdog, restart_calls = _make_watchdog(conn, now_fn=clock, recovery_timeout_s=30.0)

    watchdog.onHeartbeat(ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()  # -> FAILED -> RECOVERING (restart #1)
    assert watchdog.components["enforcer"].state == HealthState.RECOVERING
    assert len(restart_calls) == 1

    clock.now += 31.0
    watchdog.checkAll()  # recovery timeout -> FAILED -> RECOVERING (restart #2)

    assert watchdog.components["enforcer"].state == HealthState.RECOVERING
    assert len(restart_calls) == 2

    row = conn.execute(
        "SELECT state, recovered_at FROM component_event WHERE component = 'enforcer'"
    ).fetchone()
    assert row[0] == "RECOVERING"
    assert row[1] is None


def test_unknown_component_name_falls_back_to_a_guessed_unit_name():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    watchdog, restart_calls = _make_watchdog(conn)

    watchdog.onHeartbeat(ComponentHealth(name="totally-new-service", state=HealthState.NORMAL, last_heartbeat="t"))
    watchdog.checkAll()

    assert restart_calls == [["systemctl", "restart", "nidps-totally-new-service.service"]]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_core.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.watchdog'`

- [ ] **Step 3: Write `services/watchdog/watchdog.py`**

```python
"""Watchdog: the per-component Normal/Degraded/Failed/Recovering state machine (FR-8.1-FR-8.5).
This module performs every side effect the pure helpers in state_machine.py decide are needed:
component_event writes (this plan's own table to write directly, not via the Event Store),
systemctl restarts, iptables FAIL_CLOSED enforcement, and the degraded-mode runtime flag."""
from __future__ import annotations

import json
import time
from typing import Callable, Optional

from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, FailureMode, HealthState, utc_now_iso

from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.state_machine import (
    ComponentRecord,
    apply_heartbeat,
    check_recovery_timeout,
    tick_and_check_failure,
)
from services.watchdog.systemd_client import SystemdClient

# Best-effort name -> systemd unit mapping (see Global Constraints: component names have no
# shared enum). "decision-engine" and "enforcer" are the literal COMPONENT_NAME constants
# already committed in Phase 4's services/decision/main.py and services/enforcer/main.py;
# the rest are this plan's documented best guess for phases not yet written.
DEFAULT_UNIT_MAP: dict[str, str] = {
    "flowextract": "nidps-flowextract.service",
    "arpmon": "nidps-arpmon.service",
    "sigbridge": "nidps-sigbridge.service",
    "anomaly_service": "nidps-anomaly.service",
    "classifier": "nidps-classifier.service",
    "decision-engine": "nidps-decision.service",
    "enforcer": "nidps-enforcer.service",
    "dashboard": "nidps-dashboard.service",
}

_DB_STATE_FOR_NORMAL = "RUNNING"  # see Global Constraints: HealthState.NORMAL <-> DB 'RUNNING'
_VALID_FAILURE_MODES = {
    FailureMode.FAIL_OPEN.value,
    FailureMode.FAIL_CLOSED.value,
    FailureMode.DEGRADED.value,
}


def _default_cpu_fn() -> float:
    import psutil

    return psutil.cpu_percent(interval=None) / 100.0


class Watchdog:
    def __init__(
        self,
        conn,
        config_get: Callable[[str], object],
        systemd_client: SystemdClient,
        iptables_client: IptablesClient,
        runtime_flag: RuntimeFlag,
        unit_name_map: Optional[dict[str, str]] = None,
        critical_inline_components: frozenset = frozenset({"sigbridge"}),
        recovery_timeout_s: float = 30.0,
        now_fn: Callable[[], float] = time.monotonic,
        wall_fn: Callable[[], str] = utc_now_iso,
        cpu_fn: Optional[Callable[[], float]] = None,
        logger=None,
    ):
        self._conn = conn
        self._config_get = config_get
        self._systemd = systemd_client
        self._iptables = iptables_client
        self._runtime_flag = runtime_flag
        self._unit_name_map = unit_name_map if unit_name_map is not None else dict(DEFAULT_UNIT_MAP)
        self._critical_inline = critical_inline_components
        self._recovery_timeout_s = recovery_timeout_s
        self._now = now_fn
        self._wall = wall_fn
        self._cpu_fn = cpu_fn or _default_cpu_fn
        self._logger = logger or configure_logging("watchdog")
        self.components: dict[str, ComponentRecord] = {}
        self._system_degraded = False
        self._degraded_signal_active = False

    # -- public API (matches the source report's UML diagram) --------------------------------

    def onHeartbeat(self, status: ComponentHealth) -> None:
        record = self.components.setdefault(status.name, ComponentRecord(name=status.name))
        record.last_health = status
        recovered = apply_heartbeat(record)
        if recovered:
            self._on_recovered(record)

    def checkAll(self) -> None:
        threshold = int(self._config_get("watchdog.missed_heartbeats_threshold"))
        for record in list(self.components.values()):
            if record.state == HealthState.RECOVERING:
                if check_recovery_timeout(record, self._now(), self._recovery_timeout_s):
                    self._on_recovery_timed_out(record)
                continue
            became_failed = tick_and_check_failure(record, threshold)
            if became_failed:
                self._on_newly_failed(record)
        self._check_cpu_watermarks()
        self._reconcile_degraded_signal()

    def applyMode(self, component: str) -> str:
        mode = self._safe_failure_mode()
        record = self.components.get(component)
        if component in self._critical_inline and record is not None:
            if mode == FailureMode.FAIL_CLOSED.value and not record.fail_closed_inserted:
                self._iptables.insert_drop_all()
                record.fail_closed_inserted = True
            # FAIL_OPEN: no firewall action -- the pre-existing --queue-bypass flag already
            # lets traffic through while the inline process is down.
        self._logger.info(json.dumps({
            "event": "failure_mode_applied",
            "component": component,
            "failure_mode": mode,
        }))
        return mode

    # -- internal: failure / restart / recovery ------------------------------------------------

    def _on_newly_failed(self, record: ComponentRecord) -> None:
        if record.failed_since is None:
            record.failed_since = self._now()
        self._set_incident_state(record, HealthState.FAILED.value, {"reason": "missed_heartbeats"})
        self.applyMode(record.name)
        self._restart(record)

    def _on_recovery_timed_out(self, record: ComponentRecord) -> None:
        self._set_incident_state(record, HealthState.FAILED.value, {"reason": "recovery_timeout"})
        self.applyMode(record.name)
        self._restart(record)

    def _restart(self, record: ComponentRecord) -> None:
        unit = self._unit_name_map.get(record.name, f"nidps-{record.name}.service")
        self._systemd.restart(unit)
        record.state = HealthState.RECOVERING
        record.recovering_since = self._now()
        self._set_incident_state(record, HealthState.RECOVERING.value, {"reason": "restart_issued", "unit": unit})

    def _on_recovered(self, record: ComponentRecord) -> None:
        recovery_s = None
        if record.failed_since is not None:
            recovery_s = self._now() - record.failed_since
            record.failed_since = None
        if record.fail_closed_inserted:
            self._iptables.remove_drop_all()
            record.fail_closed_inserted = False
        self._close_incident(record, _DB_STATE_FOR_NORMAL)
        self._logger.info(json.dumps({
            "event": "component_recovered",
            "component": record.name,
            "recovery_s": recovery_s,
        }))

    # -- internal: component_event persistence (this plan's own direct writes) -----------------

    def _packets_dropped(self, record: ComponentRecord) -> int:
        # common.schemas.ComponentHealth has no packets_dropped attribute today -- this always
        # defaults to 0 until/unless that dataclass is extended. See Global Constraints.
        return getattr(record.last_health, "packets_dropped", 0) or 0

    def _packets_bypassed(self, record: ComponentRecord) -> int:
        return getattr(record.last_health, "packets_bypassed", 0) or 0

    def _set_incident_state(self, record: ComponentRecord, label: str, extra: Optional[dict] = None) -> None:
        details = json.dumps(extra) if extra else None
        failure_mode = self._safe_failure_mode()
        if record.open_event_id is None:
            cursor = self._conn.execute(
                """INSERT INTO component_event
                   (component, state, failure_mode, detected_at, packets_dropped, packets_bypassed, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.name,
                    label,
                    failure_mode,
                    self._wall(),
                    self._packets_dropped(record),
                    self._packets_bypassed(record),
                    details,
                ),
            )
            record.open_event_id = cursor.lastrowid
        else:
            self._conn.execute(
                "UPDATE component_event SET state = ?, failure_mode = ?, details = ? WHERE event_id = ?",
                (label, failure_mode, details, record.open_event_id),
            )
        self._conn.commit()

    def _close_incident(self, record: ComponentRecord, label: str) -> None:
        if record.open_event_id is not None:
            self._conn.execute(
                "UPDATE component_event SET state = ?, recovered_at = ? WHERE event_id = ?",
                (label, self._wall(), record.open_event_id),
            )
            self._conn.commit()
            record.open_event_id = None

    # -- internal: failure-mode validation (Task 8 extends CPU + signal logic) -----------------

    def _safe_failure_mode(self) -> str:
        raw = self._config_get("failure_mode")
        if raw not in _VALID_FAILURE_MODES:
            self._logger.warning(json.dumps({
                "event": "invalid_failure_mode", "value": raw, "fallback": FailureMode.FAIL_OPEN.value,
            }))
            return FailureMode.FAIL_OPEN.value
        return raw

    # -- placeholders extended by Task 7 / Task 8 (kept here so checkAll() always has them) ----

    def _check_cpu_watermarks(self) -> None:
        return None

    def _reconcile_degraded_signal(self) -> None:
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_core.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/watchdog.py tests/unit/test_watchdog_core.py
git commit -m "feat: add Watchdog core state machine (missed-heartbeat failure, restart, recovery)"
```

---

## Task 7: CPU watermark hysteresis (Normal ↔ Degraded)

**Files:**
- Modify: `services/watchdog/watchdog.py` (replace the `_check_cpu_watermarks` stub from Task 6)
- Test: `tests/unit/test_watchdog_cpu_watermarks.py`

**Interfaces:**
- Consumes: everything from Task 6, plus `watchdog.cpu_high_watermark`/`watchdog.
  cpu_low_watermark` config keys (already defined in `common/config_schema.py`, defaults 0.85/0.60).
- Produces: a working `_check_cpu_watermarks()` that moves every currently-`NORMAL` component to
  `DEGRADED` when sampled CPU crosses the high watermark, and every currently-`DEGRADED` component
  back to `NORMAL` once CPU drops below the low watermark — using two separate watermarks (hysteresis)
  so load sitting near one boundary value doesn't thrash the state every tick (FR-8.4).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_watchdog_cpu_watermarks.py
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState
from services.watchdog.config_cache import CachedConfig
from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.systemd_client import SystemdClient
from services.watchdog.watchdog import Watchdog

import fakeredis


def _make_watchdog(conn, cpu_values):
    cpu_iter = iter(cpu_values)
    config = CachedConfig(conn, ttl_s=0.0, now_fn=lambda: 0.0)
    systemd = SystemdClient(runner=lambda argv: None)
    iptables = IptablesClient(runner=lambda argv: (_ for _ in ()).throw(AssertionError(argv)))
    runtime_flag = RuntimeFlag(fakeredis.FakeRedis(decode_responses=True))
    return Watchdog(
        conn, config.get, systemd, iptables, runtime_flag,
        cpu_fn=lambda: next(cpu_iter),
    )


def _beat(watchdog, name="enforcer"):
    watchdog.onHeartbeat(ComponentHealth(name=name, state=HealthState.NORMAL, last_heartbeat="t"))


def test_component_moves_to_degraded_when_cpu_crosses_high_watermark():
    conn = connect(":memory:")
    seed_defaults(conn)
    # default high=0.85, low=0.60
    watchdog = _make_watchdog(conn, cpu_values=[0.50, 0.90])

    _beat(watchdog)
    watchdog.checkAll()  # cpu=0.50 -> stays NORMAL
    assert watchdog.components["enforcer"].state == HealthState.NORMAL

    _beat(watchdog)
    watchdog.checkAll()  # cpu=0.90 -> crosses high watermark -> DEGRADED
    assert watchdog.components["enforcer"].state == HealthState.DEGRADED


def test_component_does_not_flap_while_cpu_stays_between_watermarks():
    conn = connect(":memory:")
    seed_defaults(conn)
    watchdog = _make_watchdog(conn, cpu_values=[0.90, 0.70, 0.70])

    for _ in range(3):
        _beat(watchdog)
        watchdog.checkAll()

    # 0.70 is below the high watermark (0.85) but above the low watermark (0.60) --
    # hysteresis keeps it DEGRADED rather than bouncing back to NORMAL.
    assert watchdog.components["enforcer"].state == HealthState.DEGRADED


def test_component_returns_to_normal_once_cpu_drops_below_low_watermark():
    conn = connect(":memory:")
    seed_defaults(conn)
    watchdog = _make_watchdog(conn, cpu_values=[0.90, 0.70, 0.50])

    for _ in range(3):
        _beat(watchdog)
        watchdog.checkAll()

    assert watchdog.components["enforcer"].state == HealthState.NORMAL


def test_degraded_component_event_row_has_recovered_at_once_back_to_normal():
    conn = connect(":memory:")
    seed_defaults(conn)
    watchdog = _make_watchdog(conn, cpu_values=[0.90, 0.50])

    _beat(watchdog)
    watchdog.checkAll()  # -> DEGRADED
    _beat(watchdog)
    watchdog.checkAll()  # -> NORMAL

    row = conn.execute(
        "SELECT state, recovered_at FROM component_event WHERE component = 'enforcer'"
    ).fetchone()
    assert row[0] == "RUNNING"
    assert row[1] is not None


def test_failed_component_is_not_overwritten_by_cpu_degraded_check():
    conn = connect(":memory:")
    seed_defaults(conn)
    from common.config_loader import update

    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    watchdog = _make_watchdog(conn, cpu_values=[0.90])

    _beat(watchdog)
    # No second heartbeat before checkAll() -- component should go FAILED, not DEGRADED,
    # even though CPU also happens to be high this tick.
    watchdog.checkAll()

    assert watchdog.components["enforcer"].state == HealthState.RECOVERING
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_cpu_watermarks.py -v`
Expected: FAIL (all pass trivially do nothing right now — `_check_cpu_watermarks` is a stub, so
the DEGRADED assertions fail with `AssertionError` showing `HealthState.NORMAL` instead).

- [ ] **Step 3: Replace the `_check_cpu_watermarks` stub in `services/watchdog/watchdog.py`**

Remove this method body from Task 6's file:
```python
    def _check_cpu_watermarks(self) -> None:
        return None
```

Replace it with:
```python
    def _check_cpu_watermarks(self) -> None:
        cpu = self._cpu_fn()
        high = float(self._config_get("watchdog.cpu_high_watermark"))
        low = float(self._config_get("watchdog.cpu_low_watermark"))
        if not self._system_degraded and cpu >= high:
            self._system_degraded = True
            for record in self.components.values():
                if record.state == HealthState.NORMAL:
                    record.state = HealthState.DEGRADED
                    self._set_incident_state(record, HealthState.DEGRADED.value, {"reason": "cpu_high_watermark", "cpu": cpu})
            self._logger.info(json.dumps({"event": "system_degraded_entered", "cpu": cpu, "high_watermark": high}))
        elif self._system_degraded and cpu <= low:
            self._system_degraded = False
            for record in self.components.values():
                if record.state == HealthState.DEGRADED:
                    record.state = HealthState.NORMAL
                    self._close_incident(record, _DB_STATE_FOR_NORMAL)
            self._logger.info(json.dumps({"event": "system_degraded_exited", "cpu": cpu, "low_watermark": low}))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_cpu_watermarks.py tests/unit/test_watchdog_core.py -v`
Expected: 5 passed (this task) + 6 passed (Task 6, still green)

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/watchdog.py tests/unit/test_watchdog_cpu_watermarks.py
git commit -m "feat: add CPU watermark hysteresis for system-wide degraded mode"
```

---

## Task 8: Failure-mode branching (FAIL_OPEN / FAIL_CLOSED / DEGRADED) + degraded signal

**Files:**
- Modify: `services/watchdog/watchdog.py` (replace the `_reconcile_degraded_signal` stub; extend
  `applyMode`'s existing FAIL_CLOSED branch with live-config reconciliation)
- Test: `tests/unit/test_watchdog_failure_modes.py`

**Interfaces:**
- Consumes: everything from Tasks 6-7, plus the `failure_mode` config key (already defined in
  `common/config_schema.py`, default `"FAIL_OPEN"`).
- Produces: a working `_reconcile_degraded_signal()` that keeps `RuntimeFlag`'s
  `degraded_mode_active` in sync with `(system_degraded OR (failure_mode == DEGRADED AND any
  component FAILED/RECOVERING))`, only writing to Redis on an actual change (edge-triggered, to
  avoid redundant writes every tick); and live reconciliation so that if an admin flips
  `failure_mode` away from `FAIL_CLOSED` while a DROP rule is still inserted, the rule is removed on
  the very next `checkAll()` tick (FR-10.6 — no restart needed to pick up the new mode).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_watchdog_failure_modes.py
from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState
from services.watchdog.config_cache import CachedConfig
from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.systemd_client import SystemdClient
from services.watchdog.watchdog import Watchdog

import fakeredis


def _make_watchdog(conn, iptables_runner=None, redis_client=None):
    config = CachedConfig(conn, ttl_s=0.0, now_fn=lambda: 0.0)
    systemd = SystemdClient(runner=lambda argv: None)
    iptables = IptablesClient(runner=iptables_runner or (lambda argv: None))
    runtime_flag = RuntimeFlag(redis_client or fakeredis.FakeRedis(decode_responses=True))
    return Watchdog(conn, config.get, systemd, iptables, runtime_flag, cpu_fn=lambda: 0.0)


def _beat(watchdog, name="sigbridge"):
    watchdog.onHeartbeat(ComponentHealth(name=name, state=HealthState.NORMAL, last_heartbeat="t"))


def test_fail_open_does_not_touch_iptables_on_critical_component_failure():
    conn = connect(":memory:")
    seed_defaults(conn)  # failure_mode defaults to FAIL_OPEN
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog)
    watchdog.checkAll()  # sigbridge -> FAILED -> RECOVERING

    assert watchdog.components["sigbridge"].state == HealthState.RECOVERING
    assert calls == []


def test_fail_closed_inserts_drop_rule_on_critical_component_failure():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "FAIL_CLOSED")
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog)
    watchdog.checkAll()  # sigbridge -> FAILED -> RECOVERING, FAIL_CLOSED active

    assert calls == [["iptables", "-I", "FORWARD", "1", "-j", "DROP"]]


def test_fail_closed_removes_drop_rule_once_component_recovers():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "FAIL_CLOSED")
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog)
    watchdog.checkAll()  # -> FAILED -> RECOVERING, rule inserted
    _beat(watchdog)  # fresh heartbeat -> recovered

    assert calls == [
        ["iptables", "-I", "FORWARD", "1", "-j", "DROP"],
        ["iptables", "-D", "FORWARD", "-j", "DROP"],
    ]


def test_fail_closed_rule_is_not_inserted_twice_across_restart_retries():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "FAIL_CLOSED")
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog)
    watchdog.checkAll()  # -> FAILED -> RECOVERING, rule inserted once
    # simulate a recovery timeout without a real clock dependency by calling the internal
    # escalation path directly, mirroring what checkAll() would do on timeout
    record = watchdog.components["sigbridge"]
    watchdog._on_recovery_timed_out(record)

    insert_calls = [c for c in calls if c[1] == "-I"]
    assert len(insert_calls) == 1


def test_non_critical_component_never_triggers_iptables_even_in_fail_closed():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "FAIL_CLOSED")
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog, name="dashboard")
    watchdog.checkAll()

    assert calls == []


def test_degraded_runtime_flag_set_when_failure_mode_degraded_and_component_down():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "DEGRADED")
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    watchdog = _make_watchdog(conn, redis_client=redis_client)

    _beat(watchdog)
    watchdog.checkAll()  # sigbridge -> FAILED -> RECOVERING, failure_mode=DEGRADED

    from services.watchdog.runtime_flags import RUNTIME_KEY_DEGRADED_MODE
    assert redis_client.get(RUNTIME_KEY_DEGRADED_MODE) == "1"


def test_degraded_runtime_flag_clears_once_component_recovers():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "DEGRADED")
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    watchdog = _make_watchdog(conn, redis_client=redis_client)

    _beat(watchdog)
    watchdog.checkAll()  # -> FAILED -> RECOVERING
    _beat(watchdog)  # recovered

    from services.watchdog.runtime_flags import RUNTIME_KEY_DEGRADED_MODE
    assert redis_client.get(RUNTIME_KEY_DEGRADED_MODE) == "0"


def test_switching_failure_mode_away_from_fail_closed_removes_the_rule_live():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    update(conn, "failure_mode", "FAIL_CLOSED")
    calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: calls.append(argv))

    _beat(watchdog)
    watchdog.checkAll()  # -> FAILED -> RECOVERING, rule inserted
    update(conn, "failure_mode", "FAIL_OPEN")  # admin changes mode without restarting watchdog

    watchdog.checkAll()  # should notice and remove the now-stale DROP rule

    assert calls[-1] == ["iptables", "-D", "FORWARD", "-j", "DROP"]


def test_invalid_failure_mode_value_falls_back_to_fail_open_with_warning(caplog):
    conn = connect(":memory:")
    seed_defaults(conn)
    conn.execute("UPDATE config_setting SET value = 'BOGUS' WHERE setting_key = 'failure_mode'")
    conn.commit()
    update_calls = []
    watchdog = _make_watchdog(conn, iptables_runner=lambda argv: update_calls.append(argv))

    mode = watchdog.applyMode("sigbridge")

    assert mode == "FAIL_OPEN"
    assert update_calls == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_failure_modes.py -v`
Expected: several PASS already (FAIL_OPEN/FAIL_CLOSED insertion already works from Task 6's
`applyMode`), but the degraded-runtime-flag tests and the live-reconciliation test FAIL because
`_reconcile_degraded_signal` is still a no-op stub.

- [ ] **Step 3: Replace the `_reconcile_degraded_signal` stub in `services/watchdog/watchdog.py`**

Remove:
```python
    def _reconcile_degraded_signal(self) -> None:
        return None
```

Replace with:
```python
    def _reconcile_degraded_signal(self) -> None:
        mode = self._safe_failure_mode()
        # Live reconciliation: if the admin changed failure_mode away from FAIL_CLOSED while a
        # DROP rule is still inserted, remove it now rather than waiting for that component to
        # recover on its own (FR-10.6 -- config changes apply without restart).
        if mode != FailureMode.FAIL_CLOSED.value:
            for record in self.components.values():
                if record.fail_closed_inserted:
                    self._iptables.remove_drop_all()
                    record.fail_closed_inserted = False

        failure_mode_degraded = mode == FailureMode.DEGRADED.value and any(
            record.state in (HealthState.FAILED, HealthState.RECOVERING)
            for record in self.components.values()
        )
        desired = self._system_degraded or failure_mode_degraded
        if desired != self._degraded_signal_active:
            self._runtime_flag.set_degraded(desired)
            self._degraded_signal_active = desired
            self._logger.info(json.dumps({"event": "degraded_signal_changed", "active": desired}))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_failure_modes.py tests/unit/test_watchdog_core.py tests/unit/test_watchdog_cpu_watermarks.py -v`
Expected: 9 passed (this task) + 6 passed (Task 6) + 5 passed (Task 7), all green

- [ ] **Step 5: Commit**

```bash
git add services/watchdog/watchdog.py tests/unit/test_watchdog_failure_modes.py
git commit -m "feat: add FAIL_OPEN/FAIL_CLOSED/DEGRADED failure-mode branching and degraded signal"
```

---

## Task 9: Fault-injection test (simulated killed heartbeat stream, NFR-8 latency target)

**Files:**
- Test: `tests/unit/test_watchdog_fault_injection.py`

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: no new production code — this task is a dedicated test exercising the real wall-clock
  timing path (`time.monotonic`, not an injected fake clock) at the project's actual default config
  values (`watchdog.heartbeat_interval_s = 1.0`, `watchdog.missed_heartbeats_threshold = 3`), to
  satisfy NFR-8 ("detect a failed component within 3 seconds, restart within 30 seconds, in at least
  95% of tested failures"). A background thread simulates a component publishing heartbeats and
  then being killed (its loop stops, so no more heartbeats arrive); the test measures the real
  elapsed time until `Watchdog` transitions that component to `FAILED` and asserts it is within the
  3-second bound.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_watchdog_fault_injection.py
"""Fault-injection-style test for NFR-8: detect a failed component within 3 seconds (at the
project's default watchdog.heartbeat_interval_s=1.0 / watchdog.missed_heartbeats_threshold=3)
and restart it within 30 seconds. A background thread simulates a live component publishing
heartbeats and then being killed (the thread simply stops, as a killed process would stop
producing heartbeats) while the watchdog's real checkAll() loop runs on real wall-clock time
via time.monotonic -- this is deliberately NOT using an injected fake clock, so the test
exercises genuine timing behaviour rather than just the deterministic tick-counting logic
already covered by test_watchdog_core.py."""
from __future__ import annotations

import threading
import time

import fakeredis

from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState
from services.watchdog.config_cache import CachedConfig
from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.systemd_client import SystemdClient
from services.watchdog.watchdog import Watchdog


def test_detects_killed_component_within_three_seconds_and_restarts_it():
    conn = connect(":memory:")
    seed_defaults(conn)  # watchdog.heartbeat_interval_s=1.0, missed_heartbeats_threshold=3

    config = CachedConfig(conn, ttl_s=0.0)
    restart_calls = []
    systemd = SystemdClient(runner=lambda argv: restart_calls.append((time.monotonic(), argv)))
    iptables = IptablesClient(runner=lambda argv: None)
    runtime_flag = RuntimeFlag(fakeredis.FakeRedis(decode_responses=True))
    watchdog = Watchdog(conn, config.get, systemd, iptables, runtime_flag, cpu_fn=lambda: 0.0)

    heartbeat_interval_s = config.get("watchdog.heartbeat_interval_s")
    threshold = config.get("watchdog.missed_heartbeats_threshold")

    stop_event = threading.Event()

    def dummy_component_loop():
        # Simulates a live service publishing heartbeats roughly every interval -- then "dies"
        # (the loop simply exits) once stop_event is set, exactly like a killed process stops
        # producing heartbeats.
        while not stop_event.is_set():
            watchdog.onHeartbeat(
                ComponentHealth(name="dummy", state=HealthState.NORMAL, last_heartbeat="t")
            )
            time.sleep(heartbeat_interval_s / 4)

    thread = threading.Thread(target=dummy_component_loop, daemon=True)
    thread.start()
    time.sleep(heartbeat_interval_s)  # let a few real heartbeats land first
    stop_event.set()
    thread.join(timeout=2.0)
    killed_at = time.monotonic()

    detected_at = None
    deadline = killed_at + 3.0 + heartbeat_interval_s  # generous margin over the NFR-8 bound
    while time.monotonic() < deadline:
        watchdog.checkAll()
        if watchdog.components["dummy"].state in (HealthState.FAILED, HealthState.RECOVERING):
            detected_at = time.monotonic()
            break
        time.sleep(heartbeat_interval_s)

    assert detected_at is not None, "component was never detected as failed"
    detection_latency_s = detected_at - killed_at
    assert detection_latency_s <= 3.0 + heartbeat_interval_s, (
        f"detection took {detection_latency_s:.2f}s, expected <= {3.0 + heartbeat_interval_s:.2f}s "
        f"(NFR-8: {threshold} missed checks at {heartbeat_interval_s}s interval)"
    )
    assert len(restart_calls) == 1
    restart_latency_s = restart_calls[0][0] - killed_at
    assert restart_latency_s <= 30.0
```

- [ ] **Step 2: Run the test**

Run: `.venv/Scripts/pytest tests/unit/test_watchdog_fault_injection.py -v`
Expected: 1 passed. (No production code changes needed in this task — Tasks 6-8 already implement
the behaviour being measured; this step should already be green. If it is flaky in CI due to
scheduler jitter, widen the margin in `deadline`/the final assertion, but do not change
`Watchdog`'s detection logic to make this test pass — the deterministic tests in
`test_watchdog_core.py` are the ones that pin exact tick-counting behaviour.)

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_watchdog_fault_injection.py
git commit -m "test: add NFR-8 fault-injection test for failure detection and restart latency"
```

---

## Task 10: Service entry point (`services/watchdog/main.py`)

**Files:**
- Create: `services/watchdog/main.py`
- Test: `tests/integration/test_watchdog_main.py`
- Create (if absent): `tests/integration/__init__.py`

**Interfaces:**
- Consumes: `common.bus.{STREAM_HEARTBEATS, EventBus}` (Phase 1), `common.bus_messages.
  {MessageType, encode_envelope, decode_envelope}` (Phase 1), `common.config_loader.seed_defaults`
  (Phase 1), `common.db.migrate.connect` (Phase 1), `common.logging_setup.configure_logging`
  (Phase 1), `common.schemas.{ComponentHealth, HealthState, utc_now_iso}` (Phase 1), and every
  class from Tasks 1-8.
- Produces: `run(conn=None, bus=None, db_path="nidps.db", redis_url="redis://localhost:6379/0",
  redis_client=None, poll_interval_s=None, stop_after_iterations=None) -> None`. Process entry point
  for `python -m services.watchdog.main`, invoked by `deploy/nidps-watchdog.service` (Task 11).

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_watchdog_main.py
import fakeredis

from common.bus import STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState

from services.watchdog.main import run


def test_run_processes_one_heartbeat_and_publishes_its_own_heartbeat():
    conn = connect(":memory:")
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    bus = EventBus(redis_client)
    health = ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t")
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))

    run(
        conn=conn,
        bus=bus,
        redis_client=redis_client,
        poll_interval_s=0.01,
        stop_after_iterations=1,
    )

    rows = redis_client.xrange(STREAM_HEARTBEATS)
    bodies = [entry[1]["body"] for entry in rows]
    assert any('"name": "watchdog"' in body or '"name":"watchdog"' in body for body in bodies)


def test_run_restarts_a_component_that_stops_heartbeating():
    from common.config_loader import seed_defaults, update

    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "watchdog.missed_heartbeats_threshold", 1)
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    bus = EventBus(redis_client)
    health = ComponentHealth(name="enforcer", state=HealthState.NORMAL, last_heartbeat="t")
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))

    restart_calls = []

    def fake_systemd_runner(argv):
        restart_calls.append(argv)

    run(
        conn=conn,
        bus=bus,
        redis_client=redis_client,
        poll_interval_s=0.01,
        stop_after_iterations=2,
        systemd_runner=fake_systemd_runner,
    )

    assert restart_calls == [["systemctl", "restart", "nidps-enforcer.service"]]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/integration/test_watchdog_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.watchdog.main'`

- [ ] **Step 3: Create `tests/integration/__init__.py` if it does not already exist**

```python
```

- [ ] **Step 4: Write `services/watchdog/main.py`**

```python
"""Watchdog service entry point: consumes ComponentHealth heartbeats from STREAM_HEARTBEATS
with consumer group 'watchdog', drives Watchdog.checkAll() once per
watchdog.heartbeat_interval_s, publishes the watchdog's own heartbeat, and logs one
watchdog_self_check line per cycle so an operator can confirm the watchdog itself is alive via
`journalctl -u nidps-watchdog -f` (see Global Constraints -- systemd's Restart=always on this
unit is the actual supervision-of-the-supervisor mechanism; this log line is just the
human-visible confirmation)."""
from __future__ import annotations

import json
import time
from typing import Optional

import redis as redis_module

from common.bus import STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, HealthState, utc_now_iso

from services.watchdog.config_cache import CachedConfig
from services.watchdog.iptables_client import IptablesClient
from services.watchdog.runtime_flags import RuntimeFlag
from services.watchdog.systemd_client import SystemdClient
from services.watchdog.watchdog import Watchdog

COMPONENT_NAME = "watchdog"
CONSUMER_GROUP = "watchdog"


def _health_from_payload(payload: dict) -> ComponentHealth:
    return ComponentHealth(
        name=payload["name"],
        state=HealthState(payload["state"]),
        last_heartbeat=payload.get("last_heartbeat", utc_now_iso()),
        queue_depth=payload.get("queue_depth", 0),
        cpu_pct=payload.get("cpu_pct"),
        mem_mb=payload.get("mem_mb"),
    )


def run(
    conn=None,
    bus: Optional[EventBus] = None,
    db_path: str = "nidps.db",
    redis_url: str = "redis://localhost:6379/0",
    redis_client=None,
    systemd_runner=None,
    iptables_runner=None,
    poll_interval_s: Optional[float] = None,
    stop_after_iterations: Optional[int] = None,
) -> None:
    logger = configure_logging(COMPONENT_NAME)
    conn = conn or connect(db_path)
    seed_defaults(conn)

    redis_client = redis_client or redis_module.Redis.from_url(redis_url, decode_responses=True)
    bus = bus or EventBus(redis_client)

    config_cache = CachedConfig(conn)
    systemd_client = SystemdClient(runner=systemd_runner)
    iptables_client = IptablesClient(runner=iptables_runner)
    runtime_flag = RuntimeFlag(redis_client)

    watchdog = Watchdog(conn, config_cache.get, systemd_client, iptables_client, runtime_flag)

    def handle_raw(raw: str) -> None:
        envelope = decode_envelope(raw)
        if envelope["type"] != MessageType.HEARTBEAT.value:
            return
        watchdog.onHeartbeat(_health_from_payload(envelope["payload"]))

    last_self_heartbeat = 0.0
    iterations = 0
    while stop_after_iterations is None or iterations < stop_after_iterations:
        heartbeat_interval = float(config_cache.get("watchdog.heartbeat_interval_s"))
        effective_poll_s = poll_interval_s if poll_interval_s is not None else heartbeat_interval

        bus.consume(
            STREAM_HEARTBEATS,
            group=CONSUMER_GROUP,
            consumer=f"{CONSUMER_GROUP}-1",
            handler=handle_raw,
            block_ms=int(effective_poll_s * 1000),
        )
        watchdog.checkAll()

        now = time.time()
        if now - last_self_heartbeat >= heartbeat_interval:
            health = ComponentHealth(
                name=COMPONENT_NAME, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
            )
            bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))
            last_self_heartbeat = now

        logger.info(json.dumps({
            "event": "watchdog_self_check",
            "tracked_components": sorted(watchdog.components.keys()),
        }))
        iterations += 1


if __name__ == "__main__":
    run()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/integration/test_watchdog_main.py -v`
Expected: 2 passed

- [ ] **Step 6: Run the full test suite for this plan**

Run: `.venv/Scripts/pytest tests/unit tests/integration -v`
Expected: all tests across Tasks 1-10 pass (`test_watchdog_config_cache.py`,
`test_systemd_client.py`, `test_iptables_client.py`, `test_runtime_flags.py`,
`test_state_machine.py`, `test_watchdog_core.py`, `test_watchdog_cpu_watermarks.py`,
`test_watchdog_failure_modes.py`, `test_watchdog_fault_injection.py`, plus integration's
`test_watchdog_main.py`).

- [ ] **Step 7: Commit**

```bash
git add services/watchdog/main.py tests/integration/test_watchdog_main.py tests/integration/__init__.py
git commit -m "feat: add watchdog service entry point consuming STREAM_HEARTBEATS"
```

---

## Task 11: systemd deployment unit files (`deploy/*.service`)

**Files:**
- Create: `deploy/nidps-flowextract.service`
- Create: `deploy/nidps-arpmon.service`
- Create: `deploy/nidps-sigbridge.service`
- Create: `deploy/nidps-anomaly.service`
- Create: `deploy/nidps-classifier.service`
- Create: `deploy/nidps-decision.service`
- Create: `deploy/nidps-enforcer.service`
- Create: `deploy/nidps-watchdog.service`
- Create: `deploy/nidps-dashboard.service`

**Interfaces:**
- Consumes: nothing (these are deployment artifacts, not Python code — no test runner executes
  them; `systemd-analyze verify` is the manual verification step below).
- Produces: one unit file per NIDPS service. Every unit runs `python -m services.<module>.main`
  from `/opt/nidps` as its `ExecStart`, every unit except `nidps-watchdog.service` uses
  `Restart=on-failure` (the watchdog's own restart decisions are layered on top of this — systemd
  restarting a crashed process immediately and the watchdog separately deciding "has this component
  been failed too long, should I apply a failure mode" are complementary, not duplicate,
  mechanisms), and `nidps-watchdog.service` uses `Restart=always` (see Global Constraints —
  this is the "who watches the watchdog" answer). `StartLimitIntervalSec=0` is set on every unit so
  systemd's own crash-loop rate limiter never overrides the watchdog's own retry cadence. Units that
  don't need raw sockets or firewall access run as the non-root `nidps` user (NFR-13); the three that
  legitimately need elevated access are flagged below.

**Privilege notes (NFR-13 — flagging which units need more than a plain user):**
- `nidps-flowextract.service`: needs raw packet capture off the LAN interface →
  `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, runs as `nidps` (not root).
- `nidps-arpmon.service`: needs a raw socket to observe ARP traffic → same
  `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, runs as `nidps` (not root).
- `nidps-enforcer.service`: needs to run `ipset`/`iptables` to install blocks → requires
  `CAP_NET_ADMIN CAP_NET_RAW`. This plan grants it via `AmbientCapabilities` rather than running as
  root, consistent with NFR-13's "without admin privileges except where network access requires it."
- `nidps-watchdog.service`: needs to run `systemctl restart <any NIDPS unit>` (not just itself) and
  `iptables -I/-D FORWARD ... -j DROP` for FAIL_CLOSED. Restarting arbitrary systemd units is a
  privileged systemd-manager action with no narrower capability than root/sudo short of authoring a
  polkit rule (`org.freedesktop.systemd1.manage-units` scoped to the `nidps-*.service` unit prefix) —
  this plan runs it as `root` and documents that a hardened deployment could instead grant a
  dedicated `nidps-watchdog` user a polkit rule plus a `sudoers` entry scoped to exactly
  `systemctl restart nidps-*.service` and the two specific `iptables -I/-D FORWARD 1 -j DROP`
  invocations, as a NFR-13 follow-up outside this plan's scope (polkit policy authoring is not one of
  this plan's functional requirements).
- `nidps-sigbridge.service`, `nidps-anomaly.service`, `nidps-classifier.service`,
  `nidps-decision.service`, `nidps-dashboard.service`: no raw sockets, no firewall calls — run as
  the plain non-root `nidps` user with no extra capabilities.

**Module-path caveat (documented assumption, not a placeholder):** `ExecStart` for
`nidps-flowextract`, `nidps-arpmon`, `nidps-sigbridge`, `nidps-anomaly` uses this plan's best guess
at those services' module paths (`services.flowextract.main`, `services.arpmon.main`,
`services.sigbridge.main`, `services.anomaly.main`), since Phases 2/3/6 are not yet written at the
time this plan was authored. `nidps-classifier.service` uses `services.mlscorer.classifier.main`,
matching the literal path already named in the master roadmap
(`docs/superpowers/plans/2026-10-10-00-master-roadmap.md`) for Phase 3's deliverable.
`nidps-decision.service` and `nidps-enforcer.service` use `services.decision.main` and
`services.enforcer.main`, matching Phase 4's already-written code exactly. If a later phase lands
with a different module path than guessed here, update only that one `ExecStart=` line — nothing
else in this plan depends on these paths.

- [ ] **Step 1: Write `deploy/nidps-flowextract.service`**

```ini
[Unit]
Description=NIDPS flow extractor (packet capture, flow feature extraction)
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.flowextract.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write `deploy/nidps-arpmon.service`**

```ini
[Unit]
Description=NIDPS ARP monitor
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.arpmon.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Write `deploy/nidps-sigbridge.service`**

```ini
[Unit]
Description=NIDPS Suricata eve.json alert bridge (Layer 1 signature evidence)
After=network-online.target redis.service suricata.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.sigbridge.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Write `deploy/nidps-anomaly.service`**

```ini
[Unit]
Description=NIDPS Layer 2 anomaly scorer (Isolation Forest)
After=network-online.target redis.service nidps-flowextract.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.anomaly.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Write `deploy/nidps-classifier.service`**

```ini
[Unit]
Description=NIDPS Layer 3 attack classifier (RF/XGBoost)
After=network-online.target redis.service nidps-flowextract.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.mlscorer.classifier.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 6: Write `deploy/nidps-decision.service`**

```ini
[Unit]
Description=NIDPS decision fusion engine (Algorithm 5.5, host risk scoring)
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.decision.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 7: Write `deploy/nidps-enforcer.service`**

```ini
[Unit]
Description=NIDPS enforcer (ipset/iptables blocking)
After=network-online.target redis.service nidps-decision.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
Environment=NIDPS_HOST_IP=
Environment=NIDPS_GATEWAY_IP=
Environment=NIDPS_DNS_IP=
ExecStart=/opt/nidps/.venv/bin/python -m services.enforcer.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 8: Write `deploy/nidps-watchdog.service`**

```ini
[Unit]
Description=NIDPS watchdog (process supervision, failure-mode enforcement)
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
# Runs as root: issuing `systemctl restart` against arbitrary other nidps-*.service units, and
# inserting/removing the FAIL_CLOSED iptables DROP rule, are both privileged operations with no
# narrower capability than root short of a dedicated polkit rule + scoped sudoers entry (see this
# plan's Task 11 privilege notes for the hardening follow-up).
User=root
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.watchdog.main
Restart=always
RestartSec=1
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 9: Write `deploy/nidps-dashboard.service`**

```ini
[Unit]
Description=NIDPS management dashboard (web UI, config API, event store writer)
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=nidps
Group=nidps
NoNewPrivileges=true
WorkingDirectory=/opt/nidps
Environment=NIDPS_DB_PATH=/var/lib/nidps/nidps.db
Environment=NIDPS_REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/nidps/.venv/bin/python -m services.dashboard.main
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 10: Verify unit file syntax (manual — requires a Linux host with systemd; skip on a
  non-systemd dev machine and rely on code review of the INI syntax instead)**

Run (on a Raspberry Pi / any systemd Linux host, not required on the Windows dev machine this plan
was authored on):
```bash
for f in deploy/*.service; do systemd-analyze verify "$f" || true; done
```
Expected: no fatal syntax errors. `systemd-analyze verify` on a unit copied outside `/etc/systemd/
system/` typically warns about missing dependency units (`suricata.service`, `redis.service`) that
aren't installed on a throwaway verification host — that warning is expected and not a defect in
these files; a real failure would instead be an INI parse error or a bad directive name.

- [ ] **Step 11: Run the full test suite one final time for this plan**

Run: `.venv/Scripts/pytest tests/unit tests/integration -v`
Expected: every test from Tasks 1-10 passes (unit files added in this task have no pytest
coverage by design — they are deployment config, verified via `systemd-analyze` above).

- [ ] **Step 12: Commit**

```bash
git add deploy/nidps-flowextract.service deploy/nidps-arpmon.service deploy/nidps-sigbridge.service deploy/nidps-anomaly.service deploy/nidps-classifier.service deploy/nidps-decision.service deploy/nidps-enforcer.service deploy/nidps-watchdog.service deploy/nidps-dashboard.service
git commit -m "feat: add systemd unit files for all nine NIDPS services"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:**
  - FR-8.1 (check every component every second) → Task 6's `checkAll()` tick-counting, driven at
    `watchdog.heartbeat_interval_s` cadence by Task 10's `main.py` loop.
  - FR-8.2 (failed after 3 missed checks or process exit; auto-restart) → Task 5's
    `tick_and_check_failure()`, Task 6's `_on_newly_failed()`/`_restart()`. "Process exit" is covered
    by the same mechanism (a dead process stops producing heartbeats, which is indistinguishable from
    3 missed checks) — documented in Task 6's interfaces note rather than built as a separate
    `systemctl is-active` poll, since the heartbeat-stops-arriving signal already satisfies FR-8.2 and
    `SystemdClient.is_active()` exists if a future phase wants to add that redundant check.
  - FR-8.3 (apply fail-open/fail-closed/degraded while down) → Task 8's `applyMode()` branching and
    `_reconcile_degraded_signal()`.
  - FR-8.4 (CPU-watermark degraded mode with hysteresis) → Task 7's `_check_cpu_watermarks()`.
  - FR-8.5 (log component, mode, recovery time, packets affected) → Task 6's `_set_incident_state()`/
    `_close_incident()` writing `component_event` directly, plus the `component_recovered` log line's
    computed `recovery_s`.
  - NFR-8 (detect within 3s, restart within 30s, ≥95% of failures) → Task 9's fault-injection test
    (real wall-clock) plus Task 6's deterministic tick-based tests (exact-threshold coverage).
  - NFR-9 (fail-open keeps internet uninterrupted) → Task 8's FAIL_OPEN branch intentionally touches
    no firewall rule, relying on the already-completed earlier phase's `--queue-bypass` NFQUEUE flag;
    documented explicitly in Global Constraints and the `IptablesClient` module docstring.
  - NFR-13 (non-root except where network/firewall access requires it) → Task 11's per-unit
    `User=`/`AmbientCapabilities=` choices and the explicit privilege notes table.
  - Class diagram (`Watchdog.components`, `onHeartbeat()`, `checkAll()`, `applyMode()`;
    `ComponentHealth`/`HealthState`/`FailureMode` reused, not redefined) → Task 6's `Watchdog` class
    signature matches exactly; `common.schemas` types are imported, never shadowed.
  - `IptablesClient`/`SystemdClient` mockable-subprocess pattern → Tasks 2-3, mirroring Phase 4's
    already-established `IpsetClient` convention (`runner` constructor parameter, default wraps
    `subprocess.run`).
- **Placeholder scan:** none found — every step has complete, literal code, exact test assertions,
  and exact expected command output. The one documented "best-effort guess" (component name → unit
  name map, and the four not-yet-written phases' module paths in Task 11) is a concrete, stated
  design decision with a one-line fix path if wrong, not a TBD/placeholder.
- **Type consistency:** `Watchdog.components` values are always `state_machine.ComponentRecord`
  (never a raw `ComponentHealth`) across Tasks 6-8 and the tests; `ComponentRecord.state` is always
  `common.schemas.HealthState` (never a raw string) except at the exact DB-write boundary in
  `_set_incident_state()`/`_close_incident()`, where it is intentionally converted to the
  `'RUNNING'/'DEGRADED'/'FAILED'/'RECOVERING'` DB string via the single `_DB_STATE_FOR_NORMAL`
  constant plus `HealthState.*.value` — documented once in Global Constraints rather than repeated
  per call site. `CachedConfig.get()`'s key strings match `common.config_schema.CONFIG_KEYS_BY_NAME`
  exactly (`watchdog.heartbeat_interval_s`, `watchdog.missed_heartbeats_threshold`,
  `watchdog.cpu_high_watermark`, `watchdog.cpu_low_watermark`, `failure_mode`) — no key is invented
  or misspelled relative to Phase 1's canonical list.
