# NIDPS Flow Extraction, ARP Monitor & Layer-2 Anomaly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the passive bidirectional flow extractor (`services/flowextract/`), the ARP-spoofing
monitor (`services/arpmon/`), the Suricata `eve.json` bridge (`services/sigbridge/`), and Layer-2
anomaly detection (`services/mlscorer/anomaly.py`, `calibration.py`, `host_behaviour.py`,
`anomaly_service.py`) — four independent long-running services that together implement FR-2.5,
FR-2.6, FR-3.1-3.4, FR-4.1-4.6, FR-13.2, FR-13.3.

**Architecture:** `flowextract` passively assembles packets into bidirectional flows (Algorithm 5.1),
computes 78 running-statistic features per flow without storing packets (Welford's method, FR-3.3),
attaches JA3/JA3S TLS fingerprints (Algorithm 5.2), writes one `flow_record` row per completed/partial
flow, and publishes a `FLOW_READY` message carrying only `{flow_id, host_ip}` onto a new
`nidps:flows` Redis stream — the 78-float feature vector itself travels only inside SQLite
(`flow_record.features`), never on the bus. `arpmon` sniffs ARP frames, checks them against a trusted
IP→MAC map refreshed from dnsmasq's lease file (Algorithm 5.3), and publishes `Evidence` directly onto
`STREAM_EVIDENCE` (no DB writes — the Event Store, a separate later phase, persists `evidence` rows).
`sigbridge` tails Suricata's `eve.json` alert log and republishes each alert as `Evidence` (FR-2.6).
`mlscorer`'s Layer-2 anomaly service consumes `FLOW_READY` under its own consumer group
(`layer2-anomaly`), re-reads the 78-float vector from `flow_record.features` by `flow_id`, scores it
with a calibrated Isolation Forest (Eq 5.2-5.3, Algorithm 5.4), tracks per-host outbound-volume and
beaconing behaviour (Eq 5.4-5.5), and publishes any resulting `Evidence` onto `STREAM_EVIDENCE`.

**Tech Stack:** Python 3.11+, `scapy` (packet/TLS byte parsing, no root required for unit tests),
`scikit-learn` (`IsolationForest`), `redis`/`fakeredis` (already in `requirements.txt`), stdlib
`sqlite3`/`struct`/`hashlib`/`math`/`statistics`, `pytest`.

## Global Constraints

- Python 3.11+ (spec Table: Technology Stack). All timestamps are UTC ISO 8601 strings produced only
  via `common.schemas.utc_now_iso()` — never call `datetime.now()` directly. Packet-level timing
  inside the flow assembler uses raw POSIX epoch floats (`time.time()` or a packet's own capture
  timestamp) for sub-second arithmetic, converted to ISO strings only at the `flow_record` boundary.
- **No packet payloads or decrypted traffic are ever stored** (NFR-14, FR-11.2). `flow_record.features`
  holds only the 78 computed floats; nothing in this plan writes a `raw_packet`/`payload` column
  anywhere (none exists in the schema).
- **Table ownership (per the master roadmap's cross-cutting rules):** this plan owns `flow_record` and
  `calibration_state` (full read/write). Any service in this plan may `INSERT OR IGNORE` + `UPDATE
  last_seen` a minimal `host` row by `ip_address` when it needs a `host_id` FK; **no service in this
  plan ever writes `host.risk_score`**. `evidence` and `verdict` are written exactly once, later, by
  the Event Store — every service here that produces `Evidence` only publishes it onto
  `STREAM_EVIDENCE`, it never inserts an `evidence` row itself.
- **Evidence weight contract (cross-phase):** the (parallel, separate) decision-fusion phase reads
  `Evidence.weight` directly off the bus and never re-derives it from `Evidence.kind` — so every
  service in this plan that publishes `Evidence` is responsible for setting `.weight` itself, from the
  matching `risk.weight_*` config key, immediately before publishing:
  `SIGNATURE → risk.weight_signature`, `ANOMALY → risk.weight_anomaly`, `EXFIL → risk.weight_exfil`,
  `BEACON → risk.weight_beacon`. Each service's `main.py` does this with its own small
  `_WEIGHT_CONFIG_KEY` mapping + `_apply_weight(conn, ev)` helper (duplicated per service rather than
  shared, matching the precedent set by the decision-fusion phase's `services/enforcer/config_cache.py`
  — each phase owns tiny dependency-free utilities rather than reaching into another phase's package).
- **ArpMonitor's `EvidenceType` mapping (documented interpretation):** Phase 1's `EvidenceType` enum has
  no ARP-specific member (`SIGNATURE, ANOMALY, CLASS, EXFIL, BEACON`). ARP spoofing / gateway
  impersonation / ARP flood are all deterministic rule matches, so this plan uses
  `kind=EvidenceType.SIGNATURE` with `source=Layer.ARP` for all three, weighted by
  `risk.weight_signature` like any other SIGNATURE evidence, and distinguishes the three alert types
  via `Evidence.signature_id` (`1=ARP_SPOOF, 2=GATEWAY_IMPERSONATION, 3=ARP_FLOOD` — local sentinel
  values, not real Suricata signature IDs).
- **`onArp` return type deviates from the literal UML signature:** the class diagram shows
  `onArp(frame): Evidence` (singular), but Algorithm 5.3 lines 3-8 are three independent checks that
  can all fire for the same frame. `ArpMonitor.onArp()` returns `list[Evidence]` (possibly empty)
  instead of one nullable `Evidence`; `Detector.analyse()` wraps it as `Optional[list[Evidence]]`
  (`None` when the list is empty) to satisfy the `Detector` ABC exactly.
- **SignatureDetector flow-id gap (documented, out of scope to fix here):** Suricata's own `eve.json`
  `flow_id` is an independent ID space from this plan's `flow_record.flow_id` (two unrelated capture
  pipelines — Suricata's inline NFQUEUE capture from the already-completed Phase 0, vs. this plan's
  passive flow extractor). `SignatureDetector.ingestEveAlert()` therefore always sets
  `Evidence.flow_id = None`; `host_ip` is always populated so the decision-fusion phase's host-risk-score
  path still sees this evidence, but its per-flow correlation path cannot match a Suricata alert to a
  specific flow. A future fix (correlating by 5-tuple + timestamp proximity instead of `flow_id`) is
  explicitly out of scope for this plan.
- **Suricata severity → strength mapping (fixes a convention the decision-fusion phase already assumes
  without defining it):** that phase's Algorithm 5.5 interpretation note says "by convention the
  signature-bridge component sets `strength = 1.0` exactly for a drop-rule/severity-1 match and a lower
  value (e.g. 0.25-0.75) for lower severities" — this plan is that signature-bridge component, so
  `services/sigbridge/signature_detector.py::severity_to_strength()` implements exactly that: `1.0` if
  `alert.action == "drop"` or `alert.severity == 1`; else `0.6` for severity `2`, `0.3` for severity
  `3`, `0.25` for anything else/missing.
- **Isolation Forest score-sign mapping (Eq 5.2-5.3):** `sklearn.ensemble.IsolationForest.score_samples()`
  is documented by scikit-learn as "the opposite of the anomaly score defined in the original paper" —
  i.e. scikit-learn already computes the paper's `s(x,ψ)` internally and returns `-s(x,ψ)` (lower =
  more abnormal). This plan therefore maps `s(x,ψ) = -model.score_samples(X)`, clipped to `[0.0, 1.0]`
  to guard floating-point edge cases, and documents this as the one and only place that sign flip
  happens (`services/mlscorer/anomaly.py::_score_to_paper_convention()`). Verified empirically while
  writing this plan: fitting `IsolationForest(n_estimators=50, max_samples=64, random_state=42)` on 100
  2-D normal points and scoring 3 synthetic outliers gives `score_samples` of roughly `-0.40` to
  `-0.64` for normal points and `-0.69` to `-0.67` for the outliers — negating both ranges correctly
  puts the outliers' mapped scores (`~0.67-0.69`) above the normal points' mapped scores
  (`~0.40-00.64`), confirming "higher = more anomalous" after the sign flip.
- **Welford variance convention:** this plan uses **sample variance** (`M2/(n-1)`, `n ≥ 2`; `variance =
  0.0` and `std = 0.0` by convention when `n < 2`) everywhere a running variance is needed —
  `services/flowextract/welford.py`, `services/mlscorer/host_behaviour.py`'s EWMA trackers use the
  equivalent recursive form from Eq 5.4 directly (not Welford) since that equation is given explicitly
  in the spec. This choice (vs. population variance `M2/n`) is consistent across every module in this
  plan; no module mixes the two.
- **78-feature list (FR-3.3 — the spec states "78 features" but enumerates none; this plan defines a
  concrete, deterministic, incrementally-computable list since "compute 78 features" cannot be
  implemented as a placeholder):** `services/flowextract/features.py::FEATURE_NAMES` is a fixed
  78-element ordered list, loosely modelled on the well-known CICFlowMeter feature convention (so the
  later, separate training phase's feature semantics are recognizable) but restricted to statistics
  that can be maintained from a handful of running accumulators as packets arrive — CICFlowMeter's own
  multi-pass bulk-transfer and active/idle *sub-window* features are replaced with single-pass
  equivalents (see Task 5) since FR-3.3 explicitly forbids storing packets for a second pass. The exact
  list and formulas are given in full in Task 5 — no later task may add, remove, or reorder features
  without updating `FEATURE_NAMES` and every row already written with the old order (out of scope here
  since no training phase/consumer exists yet to be broken by this).
- **Exfiltration bucketing simplification (Eq 5.4, FR-4.5):** the spec's EWMA equation assumes a
  continuous per-bucket byte counter, but this system only observes discrete completed flows (not a
  continuous packet counter). `HostBehaviourTracker` therefore buckets by wall-clock index
  `floor(flow.end_time_epoch / exfil.bucket_seconds)`, accumulates every flow's forward/backward bytes
  for a host into the bucket matching its `end_time`, and finalizes (runs the EWMA anomaly check and
  rolls the EWMA state forward) a bucket only when a *later* flow for that same host arrives in a
  different bucket index — there is no separate timer thread. This is a documented local design
  decision, not a spec requirement.
- **`U_max` source (FR-4.5 fast path):** Algorithm 5.4 only computes `τ`, but `calibration_state.u_max`
  is a real schema column and FR-4.5's fast-path check needs a threshold from somewhere. This plan's
  calibration job computes `u_max` in the *same* weekly run as `τ`, as the `exfil.u_max_percentile`-th
  percentile of per-flow forward-byte totals seen locally during the same calibration window — a
  natural, documented extension, not a spec requirement to skip.
- **Beacon "rarely-seen local JA3" (Eq 5.5):** no config key or formula is given for what counts as
  "rare." This plan tracks, in memory, the set of distinct hosts that have ever used each JA3 string
  network-wide; a JA3 is "rare" when at most one *other* host (i.e. `<= RARE_JA3_HOST_THRESHOLD = 2`
  total distinct hosts including the current one) has ever used it. This constant lives in
  `services/mlscorer/host_behaviour.py` as a module-level constant with a docstring explaining the
  choice (same "reasonable local design decision" pattern the decision-fusion phase uses for its
  3-second correlation window) — it is deliberately not a `CONFIG_SETTING` row since it is not in the
  given config key list.
- **ARP flood threshold:** Algorithm 5.3 line 7 needs `N` (reply count) and `W` (window) with no config
  key provided for either. `ArpMonitor` takes `flood_threshold_n: int = 10` and `flood_window_s: float
  = 10.0` as constructor parameters with these documented defaults, not `CONFIG_SETTING` rows.
- **Config hot-reload (FR-10.6):** every tunable this plan reads is fetched via a small `CachedConfig`
  wrapper (5-second TTL, backed by `common.config_loader.get()`) rather than read once at startup.
  `services/flowextract/config_cache.py` and `services/mlscorer/config_cache.py` each define their own
  copy of this ~15-line class (same reasoning as the weight-mapping duplication above — no new shared
  directory outside this plan's assigned paths). `FlowAssembler.active_timeout`/`idle_timeout` are
  plain mutable `int` attributes (matching the UML class diagram exactly) that each service's
  `main.py` re-assigns from `CachedConfig` once per capture-loop iteration — `FlowAssembler` itself
  stays a simple, synchronously-testable class with no config/DB dependency.
- **Config keys consumed (names/defaults/ranges already fixed by `common/config_schema.py`, read via
  `common.config_loader.get()`, never hardcoded):** `network.active_timeout_s` (10),
  `network.idle_timeout_s` (30), `anomaly.n_estimators` (100), `anomaly.subsample_size` (256),
  `anomaly.calibration_window_hours` (48), `anomaly.calibration_percentile` (99.5),
  `anomaly.calibration_min_samples` (2000), `anomaly.calibration_max_shift` (0.15),
  `anomaly.recalibration_interval_days` (7), `exfil.ewma_alpha` (0.3), `exfil.bucket_seconds` (60),
  `exfil.k_std` (4.0), `exfil.u_max_percentile` (99.9), `beacon.min_connections` (5),
  `beacon.cv_threshold` (0.15), `retention.flow_days` (7), `watchdog.heartbeat_interval_s` (1.0),
  `risk.weight_signature` (3.0), `risk.weight_anomaly` (2.0), `risk.weight_exfil` (2.0),
  `risk.weight_beacon` (2.5).
- **`fusion.theta_c`** belongs to the Layer-3 classifier phase — not read anywhere in this plan.
- **Bootstrap model (no trained Isolation Forest exists yet from the offline training phase):**
  `services/mlscorer/anomaly.py` always takes an already-fitted `IsolationForest` via dependency
  injection (constructor argument); a `load_active_model()` helper exists for production use (queries
  `model_package` for `model_type='IFOREST' AND is_active=1`, loads the file via `joblib.load()`) but
  every test in this plan fits its own small `IsolationForest` on synthetic data with
  `sklearn.ensemble.IsolationForest` directly, and every integration test needing a `calibration_state`
  row first inserts a minimal placeholder `model_package` row (`model_type='IFOREST', version='dev',
  file_path='dev', feature_list_hash='dev', extractor_version='dev'`) itself, inline in that test.
- **Testing:** SQLite `:memory:` via `common.db.migrate.connect(":memory:")` for all DB tests;
  `fakeredis.FakeRedis(decode_responses=True)` wrapped in `common.bus.EventBus` for all bus tests;
  Scapy (`from scapy.all import IP, TCP, UDP, ARP, Ether, Raw`) crafts synthetic packets for every
  packet-parsing test — no test requires a live interface, root, or a real `eve.json`/lease file (paths
  are always constructor/function arguments, pointed at a temp file written by the test). NFR-3 (ML
  layers score each flow in ≤10ms median) is checked with a simple `time.perf_counter()` timing loop in
  Task 17's test, not a dedicated load-test harness.

---

## File Structure

```
common/
  bus.py                       # MODIFY: add STREAM_FLOWS
  bus_messages.py               # MODIFY: add MessageType.FLOW_READY
services/
  flowextract/
    __init__.py
    welford.py                  # WelfordAccumulator: running mean/sample-variance/min/max/count/sum
    five_tuple.py                # canonical_five_tuple(), PacketMeta dataclass
    tls_fingerprint.py            # Algorithm 5.2: parse_client_hello_body(), parse_server_hello_body(),
                                   #   compute_tls_fingerprint()
    features.py                    # FEATURE_NAMES (78), FlowFeatureAccumulator: update()/finalize()
    flow_assembler.py                # Algorithm 5.1: FlowAssembler (onPacket/expireIdle/emit)
    persistence.py                    # write_flow_record(), upsert_host()
    retention.py                       # purge_old_flows() (FR-13.3)
    config_cache.py                     # CachedConfig (5s TTL over common.config_loader.get())
    capture.py                           # parse_packet(scapy pkt) -> PacketMeta (scapy boundary)
    main.py                               # entry point: sniff loop -> FlowAssembler -> persistence
                                           #   -> publish FLOW_READY -> heartbeat -> periodic purge
  arpmon/
    __init__.py
    leases.py                    # parse_dnsmasq_leases(path) -> dict[ip, mac]
    arp_monitor.py                 # Algorithm 5.3: ArpMonitor(Detector), ArpFrame dataclass
    main.py                          # entry point: sniff ARP -> onArp -> publish Evidence -> heartbeat
  sigbridge/
    __init__.py
    eve_tailer.py                 # EveTailer: follows eve.json, yields alert dicts
    signature_detector.py           # SignatureDetector(Detector), severity_to_strength()
    main.py                           # entry point: tail loop -> ingestEveAlert -> publish -> heartbeat
  mlscorer/
    __init__.py
    config_cache.py                 # CachedConfig (own copy, see Global Constraints)
    calibration.py                    # Algorithm 5.4: CalibrationState, recalibrate_if_due()
    anomaly.py                          # Eq 5.2-5.3, FR-4.1-4.4: AnomalyDetector(Detector)
    host_behaviour.py                     # Eq 5.4-5.5, FR-4.5/4.6: HostBehaviourTracker
    anomaly_service.py                      # entry point: consume STREAM_FLOWS (group
                                             #   "layer2-anomaly") -> score -> publish -> heartbeat
tests/
  unit/
    test_bus.py                        # MODIFIED (STREAM_FLOWS coverage)
    test_bus_messages.py                # MODIFIED (FLOW_READY coverage)
    test_welford.py
    test_five_tuple.py
    test_tls_fingerprint.py
    test_features.py
    test_flow_assembler.py
    test_flowextract_persistence.py
    test_retention.py
    test_flowextract_capture.py
    test_flowextract_main.py
    test_leases.py
    test_arp_monitor.py
    test_arpmon_main.py
    test_eve_tailer.py
    test_signature_detector.py
    test_sigbridge_main.py
    test_calibration.py
    test_anomaly_detector.py
    test_host_behaviour.py
    test_anomaly_service.py
```

---

## Task 1: Add `STREAM_FLOWS` and `MessageType.FLOW_READY` to `common/`

**Files:**
- Modify: `common/bus.py`
- Modify: `common/bus_messages.py`
- Modify: `tests/unit/test_bus.py`
- Modify: `tests/unit/test_bus_messages.py`

**Interfaces:**
- Consumes: existing `common.bus.EventBus`, `common.bus_messages.{MessageType, encode_envelope,
  decode_envelope}` (Phase 1).
- Produces: `common.bus.STREAM_FLOWS = "nidps:flows"`; `common.bus_messages.MessageType.FLOW_READY =
  "flow_ready"`. `services/flowextract/main.py` (Task 9) publishes
  `encode_envelope(MessageType.FLOW_READY, {"flow_id": int, "host_ip": str})` onto `STREAM_FLOWS` after
  every `flow_record` insert; `services/mlscorer/anomaly_service.py` (Task 20) consumes it under
  consumer group `"layer2-anomaly"`. A later, separate Layer-3 phase consumes the same stream under its
  own group (e.g. `"layer3-classifier"`) — no coordination needed beyond this fixed contract.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_bus.py`:
```python
from common.bus import STREAM_FLOWS


def test_stream_flows_name_is_fixed():
    assert STREAM_FLOWS == "nidps:flows"


def test_publish_and_consume_on_stream_flows():
    import fakeredis

    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_FLOWS, "flow-ready-body")

    received = []
    bus.consume(
        STREAM_FLOWS, group="layer2-anomaly", consumer="c1", handler=received.append, block_ms=100
    )
    assert received == ["flow-ready-body"]
```

Append to `tests/unit/test_bus_messages.py`:
```python
def test_flow_ready_round_trip():
    raw = encode_envelope(MessageType.FLOW_READY, {"flow_id": 42, "host_ip": "10.10.0.5"})
    envelope = decode_envelope(raw)

    assert envelope["type"] == "flow_ready"
    assert envelope["payload"] == {"flow_id": 42, "host_ip": "10.10.0.5"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_bus.py tests/unit/test_bus_messages.py -v`
Expected: FAIL — `ImportError: cannot import name 'STREAM_FLOWS' from 'common.bus'` and
`AttributeError: FLOW_READY` on `MessageType`.

- [ ] **Step 3: Add the stream constant and message type**

In `common/bus.py`, add next to the existing stream constants:
```python
STREAM_FLOWS = "nidps:flows"
```

In `common/bus_messages.py`, add a member to the existing `MessageType` enum:
```python
class MessageType(str, enum.Enum):
    EVIDENCE = "evidence"
    VERDICT = "verdict"
    HEARTBEAT = "heartbeat"
    CONFIG_CHANGE = "config_change"
    FLOW_READY = "flow_ready"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_bus.py tests/unit/test_bus_messages.py -v`
Expected: all passed (6 total: 2 new in each file plus the 4 pre-existing from Phase 1).

- [ ] **Step 5: Commit**

```bash
git add common/bus.py common/bus_messages.py tests/unit/test_bus.py tests/unit/test_bus_messages.py
git commit -m "feat: add STREAM_FLOWS and MessageType.FLOW_READY for flow-extraction bus contract"
```

---

## Task 2: Welford incremental accumulator (`services/flowextract/welford.py`)

**Files:**
- Create: `services/flowextract/__init__.py`
- Create: `services/flowextract/welford.py`
- Test: `tests/unit/test_welford.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `WelfordAccumulator` class with `add(x: float) -> None`, and properties `count: int`,
  `total: float`, `mean: float`, `variance: float` (sample variance, `M2/(n-1)`, `0.0` if `count < 2`),
  `std: float` (`sqrt(variance)`), `minimum: float` (`0.0` if `count == 0`), `maximum: float` (`0.0` if
  `count == 0`). Task 5's `FlowFeatureAccumulator` composes several instances of this class.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_welford.py
import math

from services.flowextract.welford import WelfordAccumulator


def test_empty_accumulator_defaults():
    acc = WelfordAccumulator()
    assert acc.count == 0
    assert acc.mean == 0.0
    assert acc.variance == 0.0
    assert acc.std == 0.0
    assert acc.minimum == 0.0
    assert acc.maximum == 0.0
    assert acc.total == 0.0


def test_single_value_has_zero_variance():
    acc = WelfordAccumulator()
    acc.add(10.0)
    assert acc.count == 1
    assert acc.mean == 10.0
    assert acc.variance == 0.0
    assert acc.minimum == 10.0
    assert acc.maximum == 10.0
    assert acc.total == 10.0


def test_three_values_match_hand_computed_sample_variance():
    acc = WelfordAccumulator()
    for x in (10.0, 12.0, 14.0):
        acc.add(x)

    assert acc.count == 3
    assert acc.mean == 12.0
    assert math.isclose(acc.variance, 4.0)  # M2=8.0, sample variance = 8.0 / (3-1)
    assert math.isclose(acc.std, 2.0)
    assert acc.minimum == 10.0
    assert acc.maximum == 14.0
    assert acc.total == 36.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_welford.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services'` (or `services.flowextract`).

- [ ] **Step 3: Create package markers and write `services/flowextract/welford.py`**

`services/flowextract/__init__.py`:
```python
```

`services/flowextract/welford.py`:
```python
"""Running mean/sample-variance/min/max/count accumulator (Welford's method), so flow features
(FR-3.3) are computed from a handful of floats per flow instead of storing every packet (NFR-14).
Uses SAMPLE variance (M2 / (n-1), n >= 2) consistently -- see this plan's Global Constraints."""
from __future__ import annotations

import math


class WelfordAccumulator:
    def __init__(self) -> None:
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._total = 0.0
        self._min = 0.0
        self._max = 0.0

    def add(self, x: float) -> None:
        self._count += 1
        if self._count == 1:
            self._mean = x
            self._m2 = 0.0
            self._min = x
            self._max = x
        else:
            delta = x - self._mean
            self._mean += delta / self._count
            self._m2 += delta * (x - self._mean)
            self._min = min(self._min, x)
            self._max = max(self._max, x)
        self._total += x

    @property
    def count(self) -> int:
        return self._count

    @property
    def total(self) -> float:
        return self._total

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        if self._count < 2:
            return 0.0
        return self._m2 / (self._count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def minimum(self) -> float:
        return self._min

    @property
    def maximum(self) -> float:
        return self._max
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_welford.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/__init__.py services/flowextract/welford.py tests/unit/test_welford.py
git commit -m "feat: add Welford running-statistics accumulator for flow features"
```

---

## Task 3: Canonical five-tuple key and `PacketMeta` (`services/flowextract/five_tuple.py`)

**Files:**
- Create: `services/flowextract/five_tuple.py`
- Test: `tests/unit/test_five_tuple.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `PacketMeta` dataclass (`timestamp: float, src_ip: str, dst_ip: str, src_port: int,
  dst_port: int, protocol: str, length: int, payload_len: int, tcp_flags: frozenset[str],
  tcp_window: int = 0, tls_client_hello: Optional[dict] = None,
  tls_server_hello: Optional[dict] = None`);
  `canonical_five_tuple(src_ip, src_port, dst_ip, dst_port, protocol) -> tuple` — same value
  regardless of which endpoint sent the packet, used as the `FlowTable` key in Task 6.
  `services/flowextract/capture.py` (Task 9) is the only producer of `PacketMeta`;
  `services/flowextract/flow_assembler.py` (Task 6) is its only consumer.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_five_tuple.py
from services.flowextract.five_tuple import PacketMeta, canonical_five_tuple


def test_canonical_key_same_regardless_of_direction():
    forward = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    reverse = canonical_five_tuple("93.184.216.34", 443, "10.0.0.5", 51000, "TCP")
    assert forward == reverse


def test_canonical_key_differs_by_protocol():
    tcp_key = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    udp_key = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "UDP")
    assert tcp_key != udp_key


def test_packet_meta_defaults():
    meta = PacketMeta(
        timestamp=1000.0,
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=443,
        protocol="TCP",
        length=60,
        payload_len=0,
        tcp_flags=frozenset({"SYN"}),
    )
    assert meta.tcp_window == 0
    assert meta.tls_client_hello is None
    assert meta.tls_server_hello is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_five_tuple.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.five_tuple'`

- [ ] **Step 3: Write `services/flowextract/five_tuple.py`**

```python
"""Canonical 5-tuple keying (Algorithm 5.1, line 3) so both directions of one conversation map to
the same FlowTable entry, plus the packet-level value object (PacketMeta) that decouples
FlowAssembler from Scapy -- services/flowextract/capture.py is the only module that imports Scapy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketMeta:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" or "UDP"
    length: int
    payload_len: int
    tcp_flags: frozenset
    tcp_window: int = 0
    tls_client_hello: Optional[dict] = None
    tls_server_hello: Optional[dict] = None


def canonical_five_tuple(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> tuple:
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    low, high = (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)
    return (low, high, protocol)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_five_tuple.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/five_tuple.py tests/unit/test_five_tuple.py
git commit -m "feat: add canonical five-tuple keying and PacketMeta value object"
```

---

## Task 4: JA3/JA3S TLS fingerprinting (Algorithm 5.2) (`services/flowextract/tls_fingerprint.py`)

**Files:**
- Create: `services/flowextract/tls_fingerprint.py`
- Test: `tests/unit/test_tls_fingerprint.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `GREASE_VALUES: frozenset[int]`; `parse_client_hello_body(body: bytes) -> dict` (returns
  `{"version": int, "cipher_suites": list[int], "extensions": list[int], "groups": list[int],
  "point_formats": list[int], "server_name": Optional[str]}`, parsed straight from the TLS Handshake
  body bytes — i.e. *after* the 4-byte Handshake header, not the record header);
  `parse_server_hello_body(body: bytes) -> dict` (returns `{"version": int, "cipher_suites":
  list[int] (single element), "extensions": list[int]}`); `compute_tls_fingerprint(version: int,
  cipher_suites: list[int], extensions: list[int], groups: Optional[list[int]] = None,
  point_formats: Optional[list[int]] = None) -> str` (32-character lowercase hex MD5, GREASE values
  removed from every list first). This is the **one function** (per the spec's own stated design
  constraint) that would need to change for a future JA4 migration — no other module in this plan
  computes a fingerprint string itself. `services/flowextract/capture.py` (Task 9) calls the two
  `parse_*` functions on raw TCP payload bytes and `services/flowextract/flow_assembler.py` (Task 6)
  calls `compute_tls_fingerprint()` with their output.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_tls_fingerprint.py
from services.flowextract.tls_fingerprint import (
    compute_tls_fingerprint,
    parse_client_hello_body,
    parse_server_hello_body,
)

# Hand-built TLS 1.2 ClientHello Handshake body (NOT including the 4-byte Handshake header or the
# 5-byte record header): version=0x0303, 32 zero-byte random, empty session id, cipher suites
# [0x0a0a(GREASE), 0x1301, 0x1302, 0xc02b, 0xc02f], one compression method (0x00), extensions
# [0x1a1a(GREASE, empty), 0x0000 server_name="example.com", 0x000a supported_groups=[0x001d,
# 0x0017], 0x000b ec_point_formats=[0x00], 0x0010 ALPN="h2"]. Built and verified with a
# standalone script while writing this plan -- the hex below is exactly that script's output.
CLIENT_HELLO_BODY_HEX = (
    "0303000000000000000000000000000000000000000000000000000000000000000000000a0a0a1301"
    "1302c02bc02f010000311a1a000000000010000e00000b6578616d706c652e636f6d000a0006000400"
    "1d0017000b00020100001000050003026832"
)

# Hand-built ServerHello Handshake body: version=0x0303, 32 bytes of 0x11, empty session id,
# chosen cipher 0x1301, compression 0x00, extensions [0x2a2a(GREASE, empty), 0x0000 (empty),
# 0x002b supported_versions=0x0304].
SERVER_HELLO_BODY_HEX = (
    "0303111111111111111111111111111111111111111111111111111111111111111111001301000"
    "00e2a2a000000000000002b00020304"
)


def test_parse_client_hello_body_extracts_all_fields():
    body = bytes.fromhex(CLIENT_HELLO_BODY_HEX)
    parsed = parse_client_hello_body(body)

    assert parsed["version"] == 771
    assert parsed["cipher_suites"] == [2570, 4865, 4866, 49195, 49199]
    assert parsed["extensions"] == [6682, 0, 10, 11, 16]
    assert parsed["groups"] == [29, 23]
    assert parsed["point_formats"] == [0]
    assert parsed["server_name"] == "example.com"


def test_compute_ja3_removes_grease_and_matches_known_md5():
    parsed = parse_client_hello_body(bytes.fromhex(CLIENT_HELLO_BODY_HEX))
    ja3 = compute_tls_fingerprint(
        version=parsed["version"],
        cipher_suites=parsed["cipher_suites"],
        extensions=parsed["extensions"],
        groups=parsed["groups"],
        point_formats=parsed["point_formats"],
    )
    assert ja3 == "debfe4007ee55753199d6ce73ed68dc8"


def test_parse_server_hello_body_extracts_fields():
    body = bytes.fromhex(SERVER_HELLO_BODY_HEX)
    parsed = parse_server_hello_body(body)

    assert parsed["version"] == 771
    assert parsed["cipher_suites"] == [4865]
    assert parsed["extensions"] == [10794, 0, 43]


def test_compute_ja3s_removes_grease_and_matches_known_md5():
    parsed = parse_server_hello_body(bytes.fromhex(SERVER_HELLO_BODY_HEX))
    ja3s = compute_tls_fingerprint(
        version=parsed["version"],
        cipher_suites=parsed["cipher_suites"],
        extensions=parsed["extensions"],
    )
    assert ja3s == "32c243fff40e548be0e9d43d09174766"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_tls_fingerprint.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.tls_fingerprint'`

- [ ] **Step 3: Write `services/flowextract/tls_fingerprint.py`**

```python
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


def parse_server_hello_body(body: bytes) -> dict:
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
```

Note: the `groups is None and point_formats is None` branch is what selects JA3S mode (3 fields,
exactly `s_JA3S = Version,Cipher,Extensions`) versus JA3 mode (5 fields). A real ClientHello that
happens to omit the `supported_groups`/`ec_point_formats` extensions should still pass `groups=[]`,
`point_formats=[]` explicitly (not leave them `None`) from `services/flowextract/flow_assembler.py`
(Task 6) so it is never mistaken for a ServerHello — `parse_client_hello_body()` already returns `[]`
rather than `None` for these fields, so this falls out naturally when the caller always forwards the
parser's own output.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_tls_fingerprint.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/tls_fingerprint.py tests/unit/test_tls_fingerprint.py
git commit -m "feat: add JA3/JA3S TLS fingerprinting (Algorithm 5.2)"
```

---

## Task 5: 78-feature accumulator (`services/flowextract/features.py`)

**Files:**
- Create: `services/flowextract/features.py`
- Test: `tests/unit/test_features.py`

**Interfaces:**
- Consumes: `services.flowextract.welford.WelfordAccumulator` (Task 2),
  `services.flowextract.five_tuple.PacketMeta` (Task 3).
- Produces: `FEATURE_NAMES: list[str]` (78 fixed names, order-significant);
  `FlowFeatureAccumulator` class with constructor `(protocol: str, dst_port: int)`, method
  `update(meta: PacketMeta, is_forward: bool) -> None`, method `finalize() -> list[float]` (returns
  exactly 78 floats in `FEATURE_NAMES` order — compatible with
  `common.schemas.FlowFeatures(schema_version=SCHEMA_VERSION, values=accumulator.finalize())`).
  `services/flowextract/flow_assembler.py` (Task 6) creates one `FlowFeatureAccumulator` per flow
  segment and calls `update()` once per packet, `finalize()` once at emit time.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_features.py
import math

from services.flowextract.features import FEATURE_NAMES, FlowFeatureAccumulator
from services.flowextract.five_tuple import PacketMeta


def _idx(name: str) -> int:
    return FEATURE_NAMES.index(name)


def test_feature_names_has_78_unique_entries():
    assert len(FEATURE_NAMES) == 78
    assert len(set(FEATURE_NAMES)) == 78


def test_finalize_matches_hand_verified_worked_example():
    # 5-packet TCP flow, dst_port=443: fwd@t=0 len=100 SYN win=64240; bwd@t=0.05 len=500 SYN,ACK
    # win=29200; fwd@t=0.10 len=200 ACK,PSH payload=150; bwd@t=0.25 len=80 ACK payload=20;
    # fwd@t=0.30 len=150 ACK,FIN payload=50. Every inter-packet gap is < the 1.0s sub-burst gap,
    # so the whole flow is one active burst and there is no idle period. All 78 expected values
    # below were computed and independently verified (Welford math + flag/byte counting) by hand
    # while writing this plan -- see this plan's Task 5 commentary for the full derivation.
    acc = FlowFeatureAccumulator(protocol="TCP", dst_port=443)
    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 100, 0, frozenset({"SYN"}), 64240),
        PacketMeta(0.05, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 500, 0, frozenset({"SYN", "ACK"}), 29200),
        PacketMeta(0.10, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 200, 150, frozenset({"ACK", "PSH"}), 64240),
        PacketMeta(0.25, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 80, 20, frozenset({"ACK"}), 29200),
        PacketMeta(0.30, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 150, 50, frozenset({"ACK", "FIN"}), 64240),
    ]
    directions = [True, False, True, False, True]  # fwd/bwd per packet above
    for meta, is_forward in zip(packets, directions):
        acc.update(meta, is_forward)
    values = acc.finalize()

    assert len(values) == 78
    expected = {
        "duration_s": 0.3,
        "total_fwd_packets": 3.0,
        "total_bwd_packets": 2.0,
        "total_fwd_bytes": 450.0,
        "total_bwd_bytes": 580.0,
        "flow_bytes_per_s": 3433.3333333333335,
        "flow_packets_per_s": 16.666666666666668,
        "down_up_ratio": 580.0 / 450.0,
        "fwd_pkt_len_max": 200.0,
        "fwd_pkt_len_min": 100.0,
        "fwd_pkt_len_mean": 150.0,
        "fwd_pkt_len_std": 50.0,
        "bwd_pkt_len_max": 500.0,
        "bwd_pkt_len_min": 80.0,
        "bwd_pkt_len_mean": 290.0,
        "bwd_pkt_len_std": 296.98484809834997,
        "pkt_len_min": 80.0,
        "pkt_len_max": 500.0,
        "pkt_len_mean": 206.0,
        "pkt_len_std": 170.8215443086732,
        "pkt_len_variance": 29180.0,
        "flow_iat_mean": 0.075,
        "flow_iat_std": 0.05,
        "flow_iat_max": 0.15,
        "flow_iat_min": 0.05,
        "fwd_iat_total": 0.3,
        "fwd_iat_mean": 0.15,
        "fwd_iat_std": 0.07071067811865474,
        "fwd_iat_max": 0.2,
        "fwd_iat_min": 0.1,
        "bwd_iat_total": 0.2,
        "bwd_iat_mean": 0.2,
        "bwd_iat_std": 0.0,
        "bwd_iat_max": 0.2,
        "bwd_iat_min": 0.2,
        "fwd_packets_per_s": 10.0,
        "bwd_packets_per_s": 6.666666666666667,
        "fin_flag_count": 1.0,
        "syn_flag_count": 2.0,
        "rst_flag_count": 0.0,
        "psh_flag_count": 1.0,
        "ack_flag_count": 4.0,
        "urg_flag_count": 0.0,
        "cwe_flag_count": 0.0,
        "ece_flag_count": 0.0,
        "fwd_psh_flags": 1.0,
        "bwd_psh_flags": 0.0,
        "fwd_urg_flags": 0.0,
        "bwd_urg_flags": 0.0,
        "fwd_header_length": 250.0,
        "bwd_header_length": 560.0,
        "avg_packet_size": 206.0,
        "avg_fwd_segment_size": 150.0,
        "avg_bwd_segment_size": 290.0,
        "subflow_fwd_packets": 3.0,
        "subflow_fwd_bytes": 450.0,
        "subflow_bwd_packets": 2.0,
        "subflow_bwd_bytes": 580.0,
        "init_win_bytes_fwd": 64240.0,
        "init_win_bytes_bwd": 29200.0,
        "act_data_pkt_fwd": 2.0,
        "min_seg_size_fwd": 50.0,
        "protocol_tcp": 1.0,
        "protocol_udp": 0.0,
        "active_mean": 0.3,
        "active_std": 0.0,
        "active_max": 0.3,
        "active_min": 0.3,
        "idle_mean": 0.0,
        "idle_std": 0.0,
        "idle_max": 0.0,
        "idle_min": 0.0,
        "dst_port_numeric": 443.0,
        "fwd_bytes_per_s": 1500.0,
        "bwd_bytes_per_s": 1933.3333333333335,
        "fwd_pkt_len_variance": 2500.0,
        "bwd_pkt_len_variance": 88200.0,
        "flow_iat_variance": 0.0025,
    }
    assert len(expected) == 78
    for name, expected_value in expected.items():
        assert math.isclose(values[_idx(name)], expected_value, rel_tol=1e-9, abs_tol=1e-9), name
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/unit/test_features.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.features'`

- [ ] **Step 3: Write `services/flowextract/features.py`**

```python
"""FR-3.3: computes the fixed 78-feature vector for one flow (segment) incrementally, as packets
arrive, without storing them (NFR-14). Loosely modelled on the CICFlowMeter feature convention for
recognizability by a later training phase, but every feature here is a single-pass running
statistic -- see this plan's Global Constraints for why the mapping isn't a literal CICFlowMeter
port. SUBFLOW_ACTIVITY_GAP_S partitions one flow's packets into active bursts / idle gaps for the
active_*/idle_* features; it is a local design constant, independent of the flow-level
active/idle *timeouts* that govern when FlowAssembler emits a whole flow (Task 6)."""
from __future__ import annotations

from typing import Optional

from services.flowextract.five_tuple import PacketMeta
from services.flowextract.welford import WelfordAccumulator

SUBFLOW_ACTIVITY_GAP_S = 1.0

FEATURE_NAMES = [
    "duration_s", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
    "flow_bytes_per_s", "flow_packets_per_s", "down_up_ratio",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_variance",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_packets_per_s", "bwd_packets_per_s",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length",
    "avg_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_fwd", "init_win_bytes_bwd", "act_data_pkt_fwd", "min_seg_size_fwd",
    "protocol_tcp", "protocol_udp",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "dst_port_numeric", "fwd_bytes_per_s", "bwd_bytes_per_s",
    "fwd_pkt_len_variance", "bwd_pkt_len_variance", "flow_iat_variance",
]
assert len(FEATURE_NAMES) == 78


class FlowFeatureAccumulator:
    def __init__(self, protocol: str, dst_port: int) -> None:
        self._protocol = protocol
        self._dst_port = dst_port

        self.fwd_len = WelfordAccumulator()
        self.bwd_len = WelfordAccumulator()
        self.all_len = WelfordAccumulator()
        self.flow_iat = WelfordAccumulator()
        self.fwd_iat = WelfordAccumulator()
        self.bwd_iat = WelfordAccumulator()
        self.fwd_header = WelfordAccumulator()
        self.bwd_header = WelfordAccumulator()
        self.active = WelfordAccumulator()
        self.idle = WelfordAccumulator()

        self._flag_counts = {f: 0 for f in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE")}
        self._fwd_psh = 0
        self._bwd_psh = 0
        self._fwd_urg = 0
        self._bwd_urg = 0
        self._act_data_pkt_fwd = 0
        self._init_win_fwd: Optional[int] = None
        self._init_win_bwd: Optional[int] = None

        self._first_time: Optional[float] = None
        self._last_time: Optional[float] = None
        self._last_fwd_time: Optional[float] = None
        self._last_bwd_time: Optional[float] = None
        self._burst_start: Optional[float] = None
        self._burst_last: Optional[float] = None

    def update(self, meta: PacketMeta, is_forward: bool) -> None:
        if self._first_time is None:
            self._first_time = meta.timestamp
            self._burst_start = meta.timestamp
        else:
            iat = meta.timestamp - self._last_time
            self.flow_iat.add(iat)
            if iat >= SUBFLOW_ACTIVITY_GAP_S:
                self.active.add(self._burst_last - self._burst_start)
                self.idle.add(iat)
                self._burst_start = meta.timestamp
        self._burst_last = meta.timestamp
        self._last_time = meta.timestamp

        header_len = max(meta.length - meta.payload_len, 0)
        self.all_len.add(meta.length)

        if is_forward:
            self.fwd_len.add(meta.length)
            self.fwd_header.add(header_len)
            if self._last_fwd_time is not None:
                self.fwd_iat.add(meta.timestamp - self._last_fwd_time)
            self._last_fwd_time = meta.timestamp
            if meta.payload_len > 0:
                self._act_data_pkt_fwd += 1
            if "SYN" in meta.tcp_flags and self._init_win_fwd is None:
                self._init_win_fwd = meta.tcp_window
            if "PSH" in meta.tcp_flags:
                self._fwd_psh += 1
            if "URG" in meta.tcp_flags:
                self._fwd_urg += 1
        else:
            self.bwd_len.add(meta.length)
            self.bwd_header.add(header_len)
            if self._last_bwd_time is not None:
                self.bwd_iat.add(meta.timestamp - self._last_bwd_time)
            self._last_bwd_time = meta.timestamp
            if "SYN" in meta.tcp_flags and self._init_win_bwd is None:
                self._init_win_bwd = meta.tcp_window
            if "PSH" in meta.tcp_flags:
                self._bwd_psh += 1
            if "URG" in meta.tcp_flags:
                self._bwd_urg += 1

        for flag in meta.tcp_flags:
            if flag in self._flag_counts:
                self._flag_counts[flag] += 1

    def finalize(self) -> list:
        if self._burst_start is not None and self._burst_last is not None:
            self.active.add(self._burst_last - self._burst_start)

        duration = (self._last_time or 0.0) - (self._first_time or 0.0)
        duration_safe = duration if duration > 0 else 1e-6

        values_by_name = {
            "duration_s": duration,
            "total_fwd_packets": float(self.fwd_len.count),
            "total_bwd_packets": float(self.bwd_len.count),
            "total_fwd_bytes": self.fwd_len.total,
            "total_bwd_bytes": self.bwd_len.total,
            "flow_bytes_per_s": (self.fwd_len.total + self.bwd_len.total) / duration_safe,
            "flow_packets_per_s": (self.fwd_len.count + self.bwd_len.count) / duration_safe,
            "down_up_ratio": self.bwd_len.total / max(self.fwd_len.total, 1.0),
            "fwd_pkt_len_max": self.fwd_len.maximum,
            "fwd_pkt_len_min": self.fwd_len.minimum,
            "fwd_pkt_len_mean": self.fwd_len.mean,
            "fwd_pkt_len_std": self.fwd_len.std,
            "bwd_pkt_len_max": self.bwd_len.maximum,
            "bwd_pkt_len_min": self.bwd_len.minimum,
            "bwd_pkt_len_mean": self.bwd_len.mean,
            "bwd_pkt_len_std": self.bwd_len.std,
            "pkt_len_min": self.all_len.minimum,
            "pkt_len_max": self.all_len.maximum,
            "pkt_len_mean": self.all_len.mean,
            "pkt_len_std": self.all_len.std,
            "pkt_len_variance": self.all_len.variance,
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.maximum,
            "flow_iat_min": self.flow_iat.minimum,
            "fwd_iat_total": self.fwd_iat.total,
            "fwd_iat_mean": self.fwd_iat.mean,
            "fwd_iat_std": self.fwd_iat.std,
            "fwd_iat_max": self.fwd_iat.maximum,
            "fwd_iat_min": self.fwd_iat.minimum,
            "bwd_iat_total": self.bwd_iat.total,
            "bwd_iat_mean": self.bwd_iat.mean,
            "bwd_iat_std": self.bwd_iat.std,
            "bwd_iat_max": self.bwd_iat.maximum,
            "bwd_iat_min": self.bwd_iat.minimum,
            "fwd_packets_per_s": self.fwd_len.count / duration_safe,
            "bwd_packets_per_s": self.bwd_len.count / duration_safe,
            "fin_flag_count": float(self._flag_counts["FIN"]),
            "syn_flag_count": float(self._flag_counts["SYN"]),
            "rst_flag_count": float(self._flag_counts["RST"]),
            "psh_flag_count": float(self._flag_counts["PSH"]),
            "ack_flag_count": float(self._flag_counts["ACK"]),
            "urg_flag_count": float(self._flag_counts["URG"]),
            "cwe_flag_count": float(self._flag_counts["CWE"]),
            "ece_flag_count": float(self._flag_counts["ECE"]),
            "fwd_psh_flags": float(self._fwd_psh),
            "bwd_psh_flags": float(self._bwd_psh),
            "fwd_urg_flags": float(self._fwd_urg),
            "bwd_urg_flags": float(self._bwd_urg),
            "fwd_header_length": self.fwd_header.total,
            "bwd_header_length": self.bwd_header.total,
            "avg_packet_size": self.all_len.mean,
            "avg_fwd_segment_size": self.fwd_len.mean,
            "avg_bwd_segment_size": self.bwd_len.mean,
            "subflow_fwd_packets": float(self.fwd_len.count),
            "subflow_fwd_bytes": self.fwd_len.total,
            "subflow_bwd_packets": float(self.bwd_len.count),
            "subflow_bwd_bytes": self.bwd_len.total,
            "init_win_bytes_fwd": float(self._init_win_fwd or 0),
            "init_win_bytes_bwd": float(self._init_win_bwd or 0),
            "act_data_pkt_fwd": float(self._act_data_pkt_fwd),
            "min_seg_size_fwd": self.fwd_header.minimum,
            "protocol_tcp": 1.0 if self._protocol == "TCP" else 0.0,
            "protocol_udp": 1.0 if self._protocol == "UDP" else 0.0,
            "active_mean": self.active.mean,
            "active_std": self.active.std,
            "active_max": self.active.maximum,
            "active_min": self.active.minimum,
            "idle_mean": self.idle.mean,
            "idle_std": self.idle.std,
            "idle_max": self.idle.maximum,
            "idle_min": self.idle.minimum,
            "dst_port_numeric": float(self._dst_port),
            "fwd_bytes_per_s": self.fwd_len.total / duration_safe,
            "bwd_bytes_per_s": self.bwd_len.total / duration_safe,
            "fwd_pkt_len_variance": self.fwd_len.variance,
            "bwd_pkt_len_variance": self.bwd_len.variance,
            "flow_iat_variance": self.flow_iat.variance,
        }
        return [values_by_name[name] for name in FEATURE_NAMES]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/unit/test_features.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/features.py tests/unit/test_features.py
git commit -m "feat: add 78-feature running accumulator for flow records (FR-3.3)"
```

---

## Task 6: `FlowAssembler` (Algorithm 5.1) (`services/flowextract/flow_assembler.py`)

**Files:**
- Create: `services/flowextract/flow_assembler.py`
- Test: `tests/unit/test_flow_assembler.py`

**Interfaces:**
- Consumes: `services.flowextract.five_tuple.{PacketMeta, canonical_five_tuple}` (Task 3),
  `services.flowextract.features.FlowFeatureAccumulator` (Task 5),
  `services.flowextract.tls_fingerprint.compute_tls_fingerprint` (Task 4),
  `common.schemas.TLSFingerprint` (Phase 1).
- Produces: `EmittedFlow` dataclass (`src_ip, dst_ip, src_port, dst_port, protocol, start_time: float,
  end_time: float, segment_no: int, is_partial: bool, feature_values: list[float],
  tls: TLSFingerprint`); `FlowAssembler` class — attrs `flow_table: dict` (matches the UML
  `flowTable: map`), `active_timeout: int`, `idle_timeout: int` (plain mutable ints, matching the UML
  class diagram exactly — re-assigned by `main.py` each capture-loop iteration per FR-10.6, see Global
  Constraints); methods `onPacket(meta: PacketMeta) -> list[EmittedFlow]` (emits caused by *this*
  packet: FIN-both-directions/RST → full emit + key removed; active-timeout crossed → partial emit +
  key kept, `segment_no` incremented), `expireIdle(now: float) -> list[EmittedFlow]` (emits every flow
  whose `now - last_seen >= idle_timeout`, called periodically by `main.py`), `emit(key) ->
  EmittedFlow` (matches the UML `emit(flow)` method; builds the record from the current state without
  removing the key — `onPacket`/`expireIdle` are the only callers and they own key removal).
  `services/flowextract/persistence.py` (Task 7) consumes every `EmittedFlow` this produces.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_flow_assembler.py
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.five_tuple import PacketMeta
from services.flowextract.tls_fingerprint import parse_client_hello_body

CLIENT_HELLO_BODY_HEX = (
    "0303000000000000000000000000000000000000000000000000000000000000000000000a0a0a1301"
    "1302c02bc02f010000311a1a000000000010000e00000b6578616d706c652e636f6d000a0006000400"
    "1d0017000b00020100001000050003026832"
)


def test_fin_both_directions_emits_full_flow_and_removes_key():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"SYN"})),
        PacketMeta(0.01, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"SYN", "ACK"})),
        PacketMeta(0.02, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"ACK"})),
        PacketMeta(0.03, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
        PacketMeta(0.04, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
    ]
    emitted = []
    for p in packets:
        emitted.extend(asm.onPacket(p))

    assert len(emitted) == 1
    assert emitted[0].is_partial is False
    assert emitted[0].segment_no == 0
    assert emitted[0].src_ip == "10.0.0.5"
    assert emitted[0].dst_ip == "93.184.216.34"
    assert len(emitted[0].feature_values) == 78
    assert len(asm.flow_table) == 0


def test_rst_emits_full_flow_immediately():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    asm.onPacket(PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"})))
    emitted = asm.onPacket(
        PacketMeta(0.01, "1.2.3.4", "10.0.0.5", 80, 51000, "TCP", 60, 0, frozenset({"RST"}))
    )
    assert len(emitted) == 1
    assert emitted[0].is_partial is False
    assert len(asm.flow_table) == 0


def test_active_timeout_emits_partial_and_keeps_key_with_incremented_segment():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    first = PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"}))
    second = PacketMeta(15.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 10, frozenset({"ACK"}))

    assert asm.onPacket(first) == []
    emitted = asm.onPacket(second)

    assert len(emitted) == 1
    assert emitted[0].is_partial is True
    assert emitted[0].segment_no == 0
    assert len(asm.flow_table) == 1
    kept_state = next(iter(asm.flow_table.values()))
    assert kept_state.segment_no == 1


def test_expire_idle_emits_full_flow_and_removes_key():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    asm.onPacket(PacketMeta(0.0, "10.0.0.9", "5.6.7.8", 51000, 53, "UDP", 60, 40, frozenset()))

    assert len(asm.flow_table) == 1
    expired = asm.expireIdle(now=31.0)

    assert len(expired) == 1
    assert expired[0].is_partial is False
    assert len(asm.flow_table) == 0


def test_tls_client_hello_attaches_ja3_to_flow():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    parsed = parse_client_hello_body(bytes.fromhex(CLIENT_HELLO_BODY_HEX))
    hello_packet = PacketMeta(
        0.0, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 517, 0, frozenset({"ACK"}),
        tls_client_hello=parsed,
    )
    asm.onPacket(hello_packet)
    expired = asm.expireIdle(now=100.0)

    assert expired[0].tls.ja3 == "debfe4007ee55753199d6ce73ed68dc8"
    assert expired[0].tls.server_name == "example.com"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_flow_assembler.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.flow_assembler'`

- [ ] **Step 3: Write `services/flowextract/flow_assembler.py`**

```python
"""Algorithm 5.1: bidirectional flow assembly. FlowAssembler.active_timeout/idle_timeout are
plain mutable ints (matching the UML class diagram) -- main.py (Task 9) re-assigns them from
config every capture-loop iteration (FR-10.6); this class itself has no config/DB dependency."""
from __future__ import annotations

from dataclasses import dataclass

from common.schemas import TLSFingerprint
from services.flowextract.features import FlowFeatureAccumulator
from services.flowextract.five_tuple import PacketMeta, canonical_five_tuple
from services.flowextract.tls_fingerprint import compute_tls_fingerprint


@dataclass
class EmittedFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    segment_no: int
    is_partial: bool
    feature_values: list
    tls: TLSFingerprint


class _FlowState:
    def __init__(self, fwd_tuple: tuple, protocol: str, dst_port: int, start_time: float) -> None:
        self.fwd_tuple = fwd_tuple
        self.protocol = protocol
        self.dst_port = dst_port
        self.segment_start = start_time
        self.segment_no = 0
        self.last_seen = start_time
        self.accumulator = FlowFeatureAccumulator(protocol, dst_port)
        self.tls = TLSFingerprint()
        self.fwd_fin = False
        self.bwd_fin = False
        self.rst = False


class FlowAssembler:
    def __init__(self, active_timeout: int = 10, idle_timeout: int = 30) -> None:
        self.flow_table: dict = {}
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout

    def onPacket(self, meta: PacketMeta) -> list:
        key = canonical_five_tuple(meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.protocol)
        emitted = []
        if key not in self.flow_table:
            self.flow_table[key] = _FlowState(
                (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port),
                meta.protocol, meta.dst_port, meta.timestamp,
            )
        state = self.flow_table[key]
        is_forward = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port) == state.fwd_tuple
        state.accumulator.update(meta, is_forward)
        state.last_seen = meta.timestamp

        if meta.tls_client_hello is not None:
            fields = meta.tls_client_hello
            state.tls.ja3 = compute_tls_fingerprint(
                fields["version"], fields["cipher_suites"], fields["extensions"],
                fields["groups"], fields["point_formats"],
            )
            if fields.get("server_name"):
                state.tls.server_name = fields["server_name"]
        if meta.tls_server_hello is not None:
            fields = meta.tls_server_hello
            state.tls.ja3s = compute_tls_fingerprint(
                fields["version"], fields["cipher_suites"], fields["extensions"],
            )

        if "FIN" in meta.tcp_flags:
            if is_forward:
                state.fwd_fin = True
            else:
                state.bwd_fin = True
        if "RST" in meta.tcp_flags:
            state.rst = True

        if state.rst or (state.fwd_fin and state.bwd_fin):
            emitted.append(self.emit(key))
            del self.flow_table[key]
        elif meta.timestamp - state.segment_start >= self.active_timeout:
            emitted.append(self.emit(key, is_partial=True))
            state.segment_no += 1
            state.segment_start = meta.timestamp
            state.accumulator = FlowFeatureAccumulator(meta.protocol, state.dst_port)
            state.tls = TLSFingerprint()
            state.fwd_fin = False
            state.bwd_fin = False
            state.rst = False
        return emitted

    def emit(self, key: tuple, is_partial: bool = False) -> "EmittedFlow":
        state = self.flow_table[key]
        src_ip, src_port, dst_ip, dst_port = state.fwd_tuple
        return EmittedFlow(
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            protocol=state.protocol, start_time=state.segment_start, end_time=state.last_seen,
            segment_no=state.segment_no, is_partial=is_partial,
            feature_values=state.accumulator.finalize(), tls=state.tls,
        )

    def expireIdle(self, now: float) -> list:
        emitted = []
        for key in list(self.flow_table.keys()):
            state = self.flow_table[key]
            if now - state.last_seen >= self.idle_timeout:
                emitted.append(self.emit(key))
                del self.flow_table[key]
        return emitted
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_flow_assembler.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/flow_assembler.py tests/unit/test_flow_assembler.py
git commit -m "feat: add FlowAssembler implementing bidirectional flow assembly (Algorithm 5.1)"
```

---

## Task 7: Flow persistence and host upsert (`services/flowextract/persistence.py`)

**Files:**
- Create: `services/flowextract/persistence.py`
- Test: `tests/unit/test_flowextract_persistence.py`

**Interfaces:**
- Consumes: `services.flowextract.flow_assembler.EmittedFlow` (Task 6),
  `common.schemas.{FlowFeatures, SCHEMA_VERSION, utc_now_iso}` (Phase 1), `sqlite3.Connection`
  (from `common.db.migrate.connect()`).
- Produces: `upsert_host(conn, ip_address: str, mac_address: str | None = None) -> int` (returns
  `host_id`; `INSERT OR IGNORE` then `UPDATE last_seen`, never touches `risk_score`);
  `write_flow_record(conn, emitted: EmittedFlow, host_id: int, extractor_version: str = "1.0") ->
  int` (validates the 78-float vector via `FlowFeatures.validate()` before inserting, raises
  `ValueError` on mismatch per FR-4.1's spirit of rejecting malformed vectors as early as possible;
  returns the new `flow_id`). `services/flowextract/main.py` (Task 9) calls `upsert_host()` with
  `emitted.src_ip` (the flow's forward-direction source — this plan's documented convention for which
  endpoint a flow record's `host_id` FK refers to; internal-vs-external classification is the
  decision-fusion phase's concern via `host.is_internal`, not flow extraction's) then
  `write_flow_record()`, then publishes `FLOW_READY` with that same `host_ip`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_flowextract_persistence.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_persistence.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.persistence'`

- [ ] **Step 3: Write `services/flowextract/persistence.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_persistence.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/persistence.py tests/unit/test_flowextract_persistence.py
git commit -m "feat: add flow_record persistence and host upsert helper"
```

---

## Task 8: Flow retention purge job (FR-13.3) (`services/flowextract/retention.py`)

**Files:**
- Create: `services/flowextract/retention.py`
- Test: `tests/unit/test_retention.py`

**Interfaces:**
- Consumes: `sqlite3.Connection`.
- Produces: `purge_old_flows(conn, retention_days: int) -> int` (deletes every `flow_record` row
  whose `end_time` is older than `retention_days` and returns the number of rows deleted).
  `services/flowextract/main.py` (Task 9) calls this once per purge interval (e.g. once per minute of
  main-loop iterations, not every packet) with `retention.flow_days` read from `CachedConfig`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_retention.py
from datetime import datetime, timedelta, timezone

from common.db.migrate import connect
from services.flowextract.persistence import upsert_host
from services.flowextract.retention import purge_old_flows


def _insert_flow(conn, host_id: int, end_time_iso: str) -> None:
    conn.execute(
        """INSERT INTO flow_record
               (host_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time,
                segment_no, features, extractor_version)
           VALUES (?, '10.0.0.5', '1.2.3.4', 1, 2, 'TCP', ?, ?, 0, '[]', 'dev')""",
        (host_id, end_time_iso, end_time_iso),
    )
    conn.commit()


def test_purge_deletes_only_rows_older_than_retention_window():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    now = datetime.now(timezone.utc)
    old_iso = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    recent_iso = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_flow(conn, host_id, old_iso)
    _insert_flow(conn, host_id, recent_iso)

    deleted = purge_old_flows(conn, retention_days=7)

    assert deleted == 1
    remaining = conn.execute("SELECT end_time FROM flow_record").fetchall()
    assert remaining == [(recent_iso,)]


def test_purge_returns_zero_when_nothing_is_old():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    recent_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _insert_flow(conn, host_id, recent_iso)

    assert purge_old_flows(conn, retention_days=7) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_retention.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.retention'`

- [ ] **Step 3: Write `services/flowextract/retention.py`**

```python
"""FR-13.3: deletes flow_record rows older than the retention window. The cutoff computed here is
a narrow, deliberate exception to "only utc_now_iso() stamps now" -- it is an ephemeral comparison
threshold for one DELETE statement, never persisted anywhere, and uses the exact same
'%Y-%m-%dT%H:%M:%S.%fZ' format utc_now_iso() uses so string comparison against the TEXT end_time
column sorts correctly."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def purge_old_flows(conn, retention_days: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    cursor = conn.execute("DELETE FROM flow_record WHERE end_time < ?", (cutoff,))
    conn.commit()
    return cursor.rowcount
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_retention.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/retention.py tests/unit/test_retention.py
git commit -m "feat: add flow_record retention purge job (FR-13.3)"
```

---

## Task 9: Config cache and the Scapy capture boundary (`services/flowextract/config_cache.py`, `capture.py`)

**Files:**
- Create: `services/flowextract/config_cache.py`
- Create: `services/flowextract/capture.py`
- Test: `tests/unit/test_flowextract_capture.py` (also exercises `config_cache.py`)

**Interfaces:**
- Consumes: `common.config_loader.get()` (Phase 1), `services.flowextract.five_tuple.PacketMeta`
  (Task 3), `services.flowextract.tls_fingerprint.{parse_client_hello_body,
  parse_server_hello_body}` (Task 4), `scapy.layers.inet.{IP, TCP, UDP}`, `scapy.packet.Raw`.
- Produces: `CachedConfig` class (`__init__(conn, ttl_s: float = 5.0, clock: Callable[[], float] =
  time.monotonic)`, method `get(key: str)`); `parse_packet(pkt) -> Optional[PacketMeta]` (the only
  function in this plan that imports Scapy's `IP`/`TCP`/`UDP`/`Raw` — returns `None` for anything that
  isn't IPv4 TCP/UDP). `services/flowextract/main.py` (Task 10) uses both: `CachedConfig` to re-read
  `network.active_timeout_s`/`network.idle_timeout_s`/`retention.flow_days` every loop iteration, and
  `parse_packet()` to convert every sniffed packet before handing it to `FlowAssembler.onPacket()`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_flowextract_capture.py
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.flowextract.capture import parse_packet
from services.flowextract.config_cache import CachedConfig

CLIENT_HELLO_RECORD_HEX = (
    "16030100680100006403030000000000000000000000000000000000000000000000000000000000"
    "00000000000a0a0a13011302c02bc02f010000311a1a000000000010000e00000b6578616d706c65"
    "2e636f6d000a00060004001d0017000b00020100001000050003026832"
)


def test_cached_config_returns_seeded_default():
    conn = connect(":memory:")
    seed_defaults(conn)
    cache = CachedConfig(conn)
    assert cache.get("network.active_timeout_s") == 10


def test_cached_config_serves_stale_value_until_ttl_expires():
    conn = connect(":memory:")
    seed_defaults(conn)
    fake_time = [0.0]
    cache = CachedConfig(conn, ttl_s=5.0, clock=lambda: fake_time[0])

    assert cache.get("network.active_timeout_s") == 10
    update(conn, "network.active_timeout_s", 20)
    fake_time[0] = 2.0  # still within the 5s TTL
    assert cache.get("network.active_timeout_s") == 10  # stale on purpose

    fake_time[0] = 6.0  # TTL expired
    assert cache.get("network.active_timeout_s") == 20


def test_parse_packet_extracts_tcp_metadata_and_flags():
    pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(
        sport=51000, dport=443, flags="PA", window=64240
    ) / Raw(load=b"hello")
    pkt.time = 1700000000.123

    meta = parse_packet(pkt)

    assert meta.src_ip == "10.0.0.5"
    assert meta.dst_ip == "93.184.216.34"
    assert meta.src_port == 51000
    assert meta.dst_port == 443
    assert meta.protocol == "TCP"
    assert meta.tcp_flags == frozenset({"PSH", "ACK"})
    assert meta.tcp_window == 64240
    assert meta.payload_len == 5
    assert meta.timestamp == 1700000000.123
    assert meta.tls_client_hello is None


def test_parse_packet_extracts_tls_client_hello():
    record = bytes.fromhex(CLIENT_HELLO_RECORD_HEX)
    pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(
        sport=51000, dport=443, flags="A", window=64240
    ) / Raw(load=record)
    pkt.time = 1700000000.0

    meta = parse_packet(pkt)

    assert meta.tls_client_hello is not None
    assert meta.tls_client_hello["version"] == 771
    assert meta.tls_client_hello["server_name"] == "example.com"


def test_parse_packet_ignores_non_ip_packets():
    assert parse_packet(ARP()) is None


def test_parse_packet_handles_udp():
    pkt = IP(src="10.0.0.9", dst="8.8.8.8") / UDP(sport=51000, dport=53) / Raw(load=b"dns-query")
    pkt.time = 1700000000.0

    meta = parse_packet(pkt)

    assert meta.protocol == "UDP"
    assert meta.tcp_flags == frozenset()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_capture.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.capture'` (and
`scapy` itself may also need installing first — see Step 3b).

- [ ] **Step 3a: Add `scapy` to `requirements.txt`**

Append to `requirements.txt`:
```
scapy>=2.5,<3.0
scikit-learn>=1.3,<2.0
```

Run: `.venv/Scripts/pip install -r requirements.txt`
Expected: packages install without error.

- [ ] **Step 3b: Write `services/flowextract/config_cache.py`**

```python
"""5-second-TTL cache over common.config_loader.get() so FlowAssembler's timeouts (FR-10.6) and
the retention purge interval can change at runtime without restarting this service. Deliberately
duplicated (not imported from another phase's package) in services/mlscorer/config_cache.py
(Task 17) -- each phase in this plan owns its own tiny dependency-free copy, matching the
precedent set by the decision-fusion phase's services/enforcer/config_cache.py."""
from __future__ import annotations

import time
from typing import Callable

from common import config_loader


class CachedConfig:
    def __init__(
        self, conn, ttl_s: float = 5.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._conn = conn
        self._ttl_s = ttl_s
        self._clock = clock
        self._cache: dict = {}

    def get(self, key: str):
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        value = config_loader.get(self._conn, key)
        self._cache[key] = (now, value)
        return value
```

- [ ] **Step 4: Write `services/flowextract/capture.py`**

```python
"""The only module in this plan that imports Scapy. Converts a raw Scapy packet into a
PacketMeta (Task 3). TLS records are parsed with plain struct-based byte parsing (reusing Task
4's parse_client_hello_body/parse_server_hello_body) rather than scapy.layers.tls, which needs
extra crypto dependencies this plan doesn't otherwise require."""
from __future__ import annotations

from typing import Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from services.flowextract.five_tuple import PacketMeta
from services.flowextract.tls_fingerprint import parse_client_hello_body, parse_server_hello_body

_TCP_FLAG_BITS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWE",
}


def _decode_tcp_flags(flags) -> frozenset:
    return frozenset(_TCP_FLAG_BITS[c] for c in str(flags) if c in _TCP_FLAG_BITS)


def _extract_tls_handshake(payload: bytes):
    """Returns (client_hello_fields, server_hello_fields); either may be None. Looks for a TLS
    Handshake record (content type 0x16) at the start of the TCP payload."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None, None
    record_len = int.from_bytes(payload[3:5], "big")
    handshake = payload[5 : 5 + record_len]
    if len(handshake) < 4:
        return None, None
    handshake_type = handshake[0]
    body = handshake[4:]
    if handshake_type == 0x01:
        return parse_client_hello_body(body), None
    if handshake_type == 0x02:
        return None, parse_server_hello_body(body)
    return None, None


def parse_packet(pkt) -> Optional[PacketMeta]:
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    if TCP in pkt:
        transport = pkt[TCP]
        protocol = "TCP"
        tcp_flags = _decode_tcp_flags(transport.flags)
        tcp_window = int(transport.window)
    elif UDP in pkt:
        transport = pkt[UDP]
        protocol = "UDP"
        tcp_flags = frozenset()
        tcp_window = 0
    else:
        return None

    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    client_hello = None
    server_hello = None
    if protocol == "TCP" and payload:
        client_hello, server_hello = _extract_tls_handshake(payload)

    return PacketMeta(
        timestamp=float(pkt.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        length=len(pkt),
        payload_len=len(payload),
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        tls_client_hello=client_hello,
        tls_server_hello=server_hello,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_capture.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add requirements.txt services/flowextract/config_cache.py services/flowextract/capture.py tests/unit/test_flowextract_capture.py
git commit -m "feat: add config cache and Scapy packet-parsing boundary for flow extraction"
```

---

## Task 10: flowextract entry point (`services/flowextract/main.py`)

**Files:**
- Create: `services/flowextract/main.py`
- Test: `tests/unit/test_flowextract_main.py`

**Interfaces:**
- Consumes: everything from Tasks 1-9 (`FlowAssembler`, `parse_packet`, `CachedConfig`,
  `upsert_host`, `write_flow_record`, `purge_old_flows`, `common.bus.{STREAM_FLOWS,
  STREAM_HEARTBEATS, EventBus}`, `common.bus_messages.{MessageType, encode_envelope}`,
  `common.schemas.{ComponentHealth, HealthState, utc_now_iso}`).
- Produces: `run_once(conn, bus, assembler: FlowAssembler, cached_config: CachedConfig, packets:
  list[PacketMeta], now: float) -> int` (the dependency-injected core — processes one batch of
  already-parsed packets plus one idle-expiry sweep, returns how many `FLOW_READY` messages were
  published; this is what every test in this plan calls, never `main()` itself);
  `publish_heartbeat(bus, component_name: str) -> None`; `main() -> None` (real entry point: wraps
  `run_once()` in a `scapy.sniff()` callback, re-reading config and ticking heartbeat/purge on
  wall-clock timers — not unit tested directly, matching this plan's precedent of only testing the
  dependency-injected core of every `main.py`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_flowextract_main.py
import fakeredis

from common.bus import STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.flowextract.config_cache import CachedConfig
from services.flowextract.five_tuple import PacketMeta
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.main import publish_heartbeat, run_once


def test_run_once_persists_flow_and_publishes_flow_ready():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    assembler = FlowAssembler()
    cached_config = CachedConfig(conn)

    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"SYN"})),
        PacketMeta(0.01, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"SYN", "ACK"})),
        PacketMeta(0.02, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
        PacketMeta(0.03, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
    ]
    published = run_once(conn, bus, assembler, cached_config, packets, now=0.03)

    assert published == 1
    assert conn.execute("SELECT COUNT(*) FROM flow_record").fetchone()[0] == 1

    received = []
    bus.consume(
        STREAM_FLOWS, group="layer2-anomaly", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["type"] == "flow_ready"
    assert envelope["payload"]["host_ip"] == "10.0.0.5"


def test_run_once_expires_idle_flows_with_no_new_packets():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    assembler = FlowAssembler(idle_timeout=30)
    cached_config = CachedConfig(conn)

    assembler.onPacket(
        PacketMeta(0.0, "10.0.0.9", "5.6.7.8", 51000, 53, "UDP", 60, 40, frozenset())
    )
    published = run_once(conn, bus, assembler, cached_config, [], now=31.0)

    assert published == 1
    assert len(assembler.flow_table) == 0


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    publish_heartbeat(bus, "flowextract")

    received = []
    bus.consume(
        STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["name"] == "flowextract"
    assert envelope["payload"]["state"] == "NORMAL"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.flowextract.main'`

- [ ] **Step 3: Write `services/flowextract/main.py`**

```python
"""Entry point for the flow-extraction service. run_once() is the dependency-injected core every
test calls; main() wraps it in a real scapy.sniff() loop with wall-clock-timed idle-expiry,
retention purge, and heartbeat ticks."""
from __future__ import annotations

import os
import time

from common.bus import STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.schemas import ComponentHealth, HealthState, utc_now_iso
from services.flowextract.capture import parse_packet
from services.flowextract.config_cache import CachedConfig
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.persistence import upsert_host, write_flow_record
from services.flowextract.retention import purge_old_flows

EXTRACTOR_VERSION = "1.0"


def _persist_and_publish(conn, bus: EventBus, emitted, extractor_version: str = EXTRACTOR_VERSION) -> int:
    host_id = upsert_host(conn, emitted.src_ip)
    flow_id = write_flow_record(conn, emitted, host_id, extractor_version)
    body = encode_envelope(
        MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": emitted.src_ip}
    )
    bus.publish(STREAM_FLOWS, body)
    return 1


def run_once(
    conn, bus: EventBus, assembler: FlowAssembler, cached_config: CachedConfig, packets, now: float
) -> int:
    assembler.active_timeout = cached_config.get("network.active_timeout_s")
    assembler.idle_timeout = cached_config.get("network.idle_timeout_s")
    published = 0
    for meta in packets:
        for emitted in assembler.onPacket(meta):
            published += _persist_and_publish(conn, bus, emitted)
    for emitted in assembler.expireIdle(now):
        published += _persist_and_publish(conn, bus, emitted)
    return published


def publish_heartbeat(bus: EventBus, component_name: str) -> None:
    health = ComponentHealth(
        name=component_name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
    )
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    interface = os.environ.get("NIDPS_CAPTURE_INTERFACE", "wlan0")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    assembler = FlowAssembler()
    cached_config = CachedConfig(conn)

    state = {"last_expire": time.time(), "last_purge": time.time(), "last_heartbeat": 0.0}

    from scapy.all import sniff  # imported here so no test needs a live capture backend

    def _on_packet(scapy_pkt) -> None:
        meta = parse_packet(scapy_pkt)
        if meta is not None:
            run_once(conn, bus, assembler, cached_config, [meta], now=meta.timestamp)

        now = time.time()
        heartbeat_interval = cached_config.get("watchdog.heartbeat_interval_s")
        if now - state["last_heartbeat"] >= heartbeat_interval:
            publish_heartbeat(bus, "flowextract")
            state["last_heartbeat"] = now
        if now - state["last_expire"] >= 1.0:
            run_once(conn, bus, assembler, cached_config, [], now=now)
            state["last_expire"] = now
        if now - state["last_purge"] >= 60.0:
            purge_old_flows(conn, cached_config.get("retention.flow_days"))
            state["last_purge"] = now

    sniff(iface=interface, prn=_on_packet, store=False)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_flowextract_main.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/flowextract/main.py tests/unit/test_flowextract_main.py
git commit -m "feat: add flowextract service entry point"
```

---

## Task 11: dnsmasq lease parsing (`services/arpmon/leases.py`)

**Files:**
- Create: `services/arpmon/__init__.py`
- Create: `services/arpmon/leases.py`
- Test: `tests/unit/test_leases.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_dnsmasq_leases(path: str) -> dict[str, str]` (IP → lowercase MAC; returns `{}` if
  the file doesn't exist, skips any line with fewer than 3 whitespace-separated fields). This is
  Algorithm 5.3's trusted `Bindings` source. `services/arpmon/main.py` (Task 13) calls this
  periodically (e.g. every 5s) and feeds the result into `ArpMonitor.refreshBindings()`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_leases.py
from services.arpmon.leases import parse_dnsmasq_leases


def test_parses_well_formed_lease_lines(tmp_path):
    lease_file = tmp_path / "dnsmasq.leases"
    lease_file.write_text(
        "1760000000 AA:BB:CC:DD:EE:FF 10.10.0.5 laptop 01:aa:bb:cc:dd:ee:ff\n"
        "1760000100 11:22:33:44:55:66 10.10.0.6 phone *\n"
    )

    bindings = parse_dnsmasq_leases(str(lease_file))

    assert bindings == {
        "10.10.0.5": "aa:bb:cc:dd:ee:ff",
        "10.10.0.6": "11:22:33:44:55:66",
    }


def test_skips_malformed_lines(tmp_path):
    lease_file = tmp_path / "dnsmasq.leases"
    lease_file.write_text("garbage\n1760000000 AA:BB:CC:DD:EE:FF 10.10.0.5 laptop *\n")

    bindings = parse_dnsmasq_leases(str(lease_file))

    assert bindings == {"10.10.0.5": "aa:bb:cc:dd:ee:ff"}


def test_missing_file_returns_empty_dict(tmp_path):
    missing = tmp_path / "does-not-exist.leases"
    assert parse_dnsmasq_leases(str(missing)) == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_leases.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.arpmon'`

- [ ] **Step 3: Create package marker and write `services/arpmon/leases.py`**

`services/arpmon/__init__.py`:
```python
```

`services/arpmon/leases.py`:
```python
"""Parses dnsmasq's lease file into the trusted IP->MAC map Algorithm 5.3 calls Bindings. The
path is always a function argument (never hardcoded to /var/lib/misc/dnsmasq.leases) so tests
never touch a real system file."""
from __future__ import annotations


def parse_dnsmasq_leases(path: str) -> dict:
    bindings: dict = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return bindings

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        _expiry, mac, ip = parts[0], parts[1], parts[2]
        bindings[ip] = mac.lower()
    return bindings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_leases.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/arpmon/__init__.py services/arpmon/leases.py tests/unit/test_leases.py
git commit -m "feat: add dnsmasq lease file parser for ARP bindings"
```

---

## Task 12: `ArpMonitor` (Algorithm 5.3) (`services/arpmon/arp_monitor.py`)

**Files:**
- Create: `services/arpmon/arp_monitor.py`
- Test: `tests/unit/test_arp_monitor.py`

**Interfaces:**
- Consumes: `common.detector.Detector` (Phase 1), `common.schemas.{ComponentHealth, Evidence,
  EvidenceType, HealthState, Layer, utc_now_iso}` (Phase 1).
- Produces: `ArpFrame` dataclass (`sender_ip: str, sender_mac: str, is_reply: bool,
  is_gratuitous: bool, timestamp: float`); `ArpMonitor(Detector)` class — attr `bindings: dict`
  (matches UML); constructor `(gateway_ip: str, ap_mac: str, flood_threshold_n: int = 10,
  flood_window_s: float = 10.0)`; methods `refreshBindings(leases: dict) -> None`,
  `onArp(frame: ArpFrame) -> list[Evidence]` (deviates from the literal UML singular return — see
  Global Constraints), `analyse(item: ArpFrame) -> Optional[list[Evidence]]` (Detector ABC
  requirement; wraps `onArp`), `heartbeat() -> ComponentHealth`. Every `Evidence` returned has
  `weight=0.0` — `services/arpmon/main.py` (Task 13) fills in the real weight from
  `risk.weight_signature` before publishing (see Global Constraints' weight contract).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_arp_monitor.py
from common.schemas import EvidenceType, HealthState, Layer
from services.arpmon.arp_monitor import ArpFrame, ArpMonitor


def _frame(ip, mac, t=0.0, is_reply=True, is_gratuitous=False):
    return ArpFrame(sender_ip=ip, sender_mac=mac, is_reply=is_reply, is_gratuitous=is_gratuitous, timestamp=t)


def test_request_frames_are_ignored():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    frame = _frame("10.10.0.5", "bb:bb:bb:bb:bb:bb", is_reply=False, is_gratuitous=False)
    assert monitor.onArp(frame) == []


def test_bound_ip_with_mismatched_mac_raises_spoof_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    monitor.refreshBindings({"10.10.0.5": "cc:cc:cc:cc:cc:cc"})

    evidence = monitor.onArp(_frame("10.10.0.5", "bb:bb:bb:bb:bb:bb"))

    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.SIGNATURE
    assert evidence[0].source == Layer.ARP
    assert evidence[0].signature_id == 1
    assert evidence[0].host_ip == "10.10.0.5"


def test_matching_binding_raises_no_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    monitor.refreshBindings({"10.10.0.5": "bb:bb:bb:bb:bb:bb"})

    assert monitor.onArp(_frame("10.10.0.5", "BB:BB:BB:BB:BB:BB")) == []


def test_gateway_impersonation_raises_evidence():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")

    evidence = monitor.onArp(_frame("10.10.0.1", "ff:ff:ff:ff:ff:ff"))

    assert len(evidence) == 1
    assert evidence[0].signature_id == 2


def test_flood_raises_evidence_after_threshold():
    monitor = ArpMonitor(
        gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa", flood_threshold_n=3, flood_window_s=10.0
    )
    results = [
        monitor.onArp(_frame("10.10.0.5", "bb:bb:bb:bb:bb:bb", t=float(i))) for i in range(4)
    ]
    assert results[0] == results[1] == results[2] == []
    assert len(results[3]) == 1
    assert results[3][0].signature_id == 3


def test_analyse_wraps_onarp_for_detector_interface():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    result = monitor.analyse(_frame("10.10.0.1", "ff:ff:ff:ff:ff:ff"))
    assert result[0].signature_id == 2
    assert monitor.analyse(_frame("10.10.0.9", "bb:bb:bb:bb:bb:bb")) is None


def test_heartbeat_reports_normal():
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="aa:aa:aa:aa:aa:aa")
    assert monitor.heartbeat().state == HealthState.NORMAL
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_arp_monitor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.arpmon.arp_monitor'`

- [ ] **Step 3: Write `services/arpmon/arp_monitor.py`**

```python
"""Algorithm 5.3: ARP consistency checking. onArp() returns list[Evidence] (possibly more than
one per frame, and possibly empty) -- see this plan's Global Constraints for why this deviates
from the UML's literal singular-Evidence signature; analyse() wraps it to satisfy the Detector
ABC exactly."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from common.detector import Detector
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer, utc_now_iso


@dataclass
class ArpFrame:
    sender_ip: str
    sender_mac: str
    is_reply: bool
    is_gratuitous: bool
    timestamp: float


class ArpMonitor(Detector):
    name = "arpmon"

    def __init__(
        self,
        gateway_ip: str,
        ap_mac: str,
        flood_threshold_n: int = 10,
        flood_window_s: float = 10.0,
    ) -> None:
        self.bindings: dict = {}
        self.gateway_ip = gateway_ip
        self.ap_mac = ap_mac.lower()
        self.flood_threshold_n = flood_threshold_n
        self.flood_window_s = flood_window_s
        self._reply_times: dict = {}

    def refreshBindings(self, leases: dict) -> None:
        self.bindings = dict(leases)

    def onArp(self, frame: ArpFrame) -> list:
        if not (frame.is_reply or frame.is_gratuitous):
            return []

        evidence = []
        sender_mac = frame.sender_mac.lower()

        bound_mac = self.bindings.get(frame.sender_ip)
        if bound_mac is not None and bound_mac.lower() != sender_mac:
            evidence.append(self._make_evidence(frame, signature_id=1))

        if frame.sender_ip == self.gateway_ip and sender_mac != self.ap_mac:
            evidence.append(self._make_evidence(frame, signature_id=2))

        history = self._reply_times.setdefault(sender_mac, [])
        history.append(frame.timestamp)
        window_start = frame.timestamp - self.flood_window_s
        while history and history[0] < window_start:
            history.pop(0)
        if len(history) > self.flood_threshold_n:
            evidence.append(self._make_evidence(frame, signature_id=3))

        return evidence

    def _make_evidence(self, frame: ArpFrame, signature_id: int) -> Evidence:
        return Evidence(
            source=Layer.ARP,
            flow_id=None,
            host_ip=frame.sender_ip,
            kind=EvidenceType.SIGNATURE,
            strength=1.0,
            weight=0.0,  # services/arpmon/main.py fills this from risk.weight_signature
            signature_id=signature_id,
        )

    def analyse(self, item: ArpFrame) -> Optional[list]:
        result = self.onArp(item)
        return result or None

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_arp_monitor.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add services/arpmon/arp_monitor.py tests/unit/test_arp_monitor.py
git commit -m "feat: add ArpMonitor implementing ARP consistency checking (Algorithm 5.3)"
```

---

## Task 13: arpmon entry point (`services/arpmon/main.py`)

**Files:**
- Create: `services/arpmon/main.py`
- Test: `tests/unit/test_arpmon_main.py`

**Interfaces:**
- Consumes: `services.arpmon.arp_monitor.{ArpFrame, ArpMonitor}` (Task 12),
  `services.arpmon.leases.parse_dnsmasq_leases` (Task 11), `common.bus.{STREAM_EVIDENCE,
  STREAM_HEARTBEATS, EventBus}`, `common.bus_messages.{MessageType, encode_envelope}`,
  `common.config_loader.get`.
- Produces: `parse_arp_packet(pkt, timestamp: float) -> Optional[ArpFrame]` (the only function that
  imports `scapy.layers.l2.ARP`; gratuitous = `op == 1 and psrc == pdst`, reply = `op == 2`);
  `process_frames(conn, bus: EventBus, monitor: ArpMonitor, frames: list[ArpFrame]) -> int` (the
  dependency-injected core — reads `risk.weight_signature` once, fills `.weight` on every
  `Evidence` `onArp()` returns, publishes each onto `STREAM_EVIDENCE`, returns the count published);
  `publish_heartbeat(bus, monitor: ArpMonitor) -> None`; `main() -> None` (wraps the above in a real
  `scapy.sniff(filter="arp", ...)` loop with periodic lease-file refresh and heartbeat ticks — not
  unit tested directly, same precedent as `services/flowextract/main.py`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_arpmon_main.py
import fakeredis
from scapy.layers.l2 import ARP

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.arpmon.arp_monitor import ArpMonitor
from services.arpmon.main import parse_arp_packet, process_frames, publish_heartbeat


def test_parse_arp_packet_detects_reply():
    pkt = ARP(op=2, psrc="10.10.0.5", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.10.0.1")
    frame = parse_arp_packet(pkt, timestamp=1700000000.0)

    assert frame.sender_ip == "10.10.0.5"
    assert frame.sender_mac == "aa:bb:cc:dd:ee:ff"
    assert frame.is_reply is True
    assert frame.is_gratuitous is False
    assert frame.timestamp == 1700000000.0


def test_parse_arp_packet_detects_gratuitous():
    pkt = ARP(op=1, psrc="10.10.0.9", pdst="10.10.0.9", hwsrc="11:22:33:44:55:66")
    frame = parse_arp_packet(pkt, timestamp=1700000000.0)

    assert frame.is_reply is False
    assert frame.is_gratuitous is True


def test_process_frames_fills_weight_and_publishes_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="ff:ff:ff:ff:ff:ff")

    from services.arpmon.arp_monitor import ArpFrame

    published = process_frames(
        conn, bus, monitor,
        [ArpFrame(sender_ip="10.10.0.1", sender_mac="de:ad:be:ef:00:00", is_reply=True, is_gratuitous=False, timestamp=0.0)],
    )

    assert published == 1
    received = []
    bus.consume(STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["signature_id"] == 2
    assert envelope["payload"]["weight"] == 3.0  # risk.weight_signature default


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="ff:ff:ff:ff:ff:ff")
    publish_heartbeat(bus, monitor)

    received = []
    bus.consume(STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    assert decode_envelope(received[0])["payload"]["name"] == "arpmon"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_arpmon_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.arpmon.main'`

- [ ] **Step 3: Write `services/arpmon/main.py`**

```python
"""Entry point for the ARP-spoofing monitor. process_frames() is the dependency-injected core
every test calls; main() wraps it in a real scapy.sniff() loop with periodic lease-file refresh
and heartbeat ticks."""
from __future__ import annotations

import os
import time
from typing import Optional

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from services.arpmon.arp_monitor import ArpFrame, ArpMonitor
from services.arpmon.leases import parse_dnsmasq_leases


def parse_arp_packet(pkt, timestamp: float) -> Optional[ArpFrame]:
    from scapy.layers.l2 import ARP

    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    is_reply = arp.op == 2
    is_gratuitous = arp.op == 1 and arp.psrc == arp.pdst
    return ArpFrame(
        sender_ip=arp.psrc, sender_mac=arp.hwsrc, is_reply=is_reply,
        is_gratuitous=is_gratuitous, timestamp=timestamp,
    )


def process_frames(conn, bus: EventBus, monitor: ArpMonitor, frames) -> int:
    weight = config_get(conn, "risk.weight_signature")
    published = 0
    for frame in frames:
        for ev in monitor.onArp(frame):
            ev.weight = weight
            bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
            published += 1
    return published


def publish_heartbeat(bus: EventBus, monitor: ArpMonitor) -> None:
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, monitor.heartbeat()))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    interface = os.environ.get("NIDPS_CAPTURE_INTERFACE", "wlan0")
    gateway_ip = os.environ["NIDPS_GATEWAY_IP"]
    ap_mac = os.environ["NIDPS_AP_MAC"]
    lease_path = os.environ.get("NIDPS_DHCP_LEASE_PATH", "/var/lib/misc/dnsmasq.leases")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    monitor = ArpMonitor(gateway_ip=gateway_ip, ap_mac=ap_mac)
    monitor.refreshBindings(parse_dnsmasq_leases(lease_path))

    state = {"last_lease_refresh": time.time(), "last_heartbeat": 0.0}

    from scapy.all import sniff

    def _on_packet(scapy_pkt) -> None:
        frame = parse_arp_packet(scapy_pkt, timestamp=time.time())
        if frame is not None:
            process_frames(conn, bus, monitor, [frame])

        now = time.time()
        heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
        if now - state["last_heartbeat"] >= heartbeat_interval:
            publish_heartbeat(bus, monitor)
            state["last_heartbeat"] = now
        if now - state["last_lease_refresh"] >= 5.0:
            monitor.refreshBindings(parse_dnsmasq_leases(lease_path))
            state["last_lease_refresh"] = now

    sniff(iface=interface, filter="arp", prn=_on_packet, store=False)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_arpmon_main.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/arpmon/main.py tests/unit/test_arpmon_main.py
git commit -m "feat: add arpmon service entry point"
```

---

## Task 14: `eve.json` tailer (`services/sigbridge/eve_tailer.py`)

**Files:**
- Create: `services/sigbridge/__init__.py`
- Create: `services/sigbridge/eve_tailer.py`
- Test: `tests/unit/test_eve_tailer.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `EveTailer` class — constructor `(path: str)`; method `poll() -> list[dict]` (reads any
  complete new lines appended to the file since the last call, returns only the ones with
  `event_type == "alert"` as parsed dicts; tracks a byte offset internally so repeated calls never
  re-read old lines; returns `[]` if the file doesn't exist yet). `services/sigbridge/main.py`
  (Task 16) calls `poll()` in a loop.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_eve_tailer.py
import json

from services.sigbridge.eve_tailer import EveTailer


def test_poll_returns_only_alert_events_and_tracks_offset(tmp_path):
    path = tmp_path / "eve.json"
    alert_event = {
        "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 2001219, "severity": 2, "action": "allowed"},
    }
    other_event = {"event_type": "flow", "src_ip": "10.0.0.5"}
    path.write_text(json.dumps(other_event) + "\n" + json.dumps(alert_event) + "\n")

    tailer = EveTailer(str(path))
    assert tailer.poll() == [alert_event]
    assert tailer.poll() == []

    new_alert = {
        "event_type": "alert", "src_ip": "10.0.0.9", "dest_ip": "5.6.7.8",
        "alert": {"signature_id": 1, "severity": 1, "action": "drop"},
    }
    with open(path, "a") as fh:
        fh.write(json.dumps(new_alert) + "\n")

    assert tailer.poll() == [new_alert]


def test_poll_returns_empty_list_for_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    assert EveTailer(str(missing)).poll() == []


def test_poll_ignores_malformed_json_lines(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("not-json\n")
    assert EveTailer(str(path)).poll() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_eve_tailer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.sigbridge'`

- [ ] **Step 3: Create package marker and write `services/sigbridge/eve_tailer.py`**

`services/sigbridge/__init__.py`:
```python
```

`services/sigbridge/eve_tailer.py`:
```python
"""FR-2.6: tails Suricata's eve.json alert log. Reads in binary mode and tracks a plain byte
offset (not a text-mode tell()/seek() pair) so there is no ambiguity from newline translation --
each poll() only consumes lines that end in a complete b"\\n", so a line Suricata is still
mid-writing is simply picked up on the next poll()."""
from __future__ import annotations

import json


class EveTailer:
    def __init__(self, path: str) -> None:
        self._path = path
        self._offset = 0

    def poll(self) -> list:
        alerts = []
        try:
            with open(self._path, "rb") as fh:
                fh.seek(self._offset)
                for raw_line in fh:
                    if not raw_line.endswith(b"\n"):
                        break
                    self._offset += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event_type") == "alert":
                        alerts.append(event)
        except FileNotFoundError:
            return []
        return alerts
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_eve_tailer.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add services/sigbridge/__init__.py services/sigbridge/eve_tailer.py tests/unit/test_eve_tailer.py
git commit -m "feat: add eve.json tailer for the Suricata signature bridge (FR-2.6)"
```

---

## Task 15: `SignatureDetector` (`services/sigbridge/signature_detector.py`)

**Files:**
- Create: `services/sigbridge/signature_detector.py`
- Test: `tests/unit/test_signature_detector.py`

**Interfaces:**
- Consumes: `common.detector.Detector`, `common.schemas.{ComponentHealth, Evidence, EvidenceType,
  HealthState, Layer, utc_now_iso}` (Phase 1).
- Produces: `severity_to_strength(severity: Optional[int], action: Optional[str]) -> float`
  (`1.0` if `action == "drop"` or `severity == 1`; `0.6` for severity `2`; `0.3` for severity `3`;
  `0.25` otherwise — the convention the decision-fusion phase's Algorithm 5.5 notes already assume);
  `SignatureDetector(Detector)` — method `ingestEveAlert(alert: dict) -> Evidence` (matches UML
  exactly; `flow_id` is always `None` — see Global Constraints' documented flow-id gap), `analyse(item:
  dict) -> Optional[list[Evidence]]`, `heartbeat() -> ComponentHealth`.
  `services/sigbridge/main.py` (Task 16) calls `ingestEveAlert()` for every alert `EveTailer.poll()`
  returns.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_signature_detector.py
from common.schemas import EvidenceType, Layer
from services.sigbridge.signature_detector import SignatureDetector, severity_to_strength


def test_severity_to_strength_drop_or_severity1_is_max():
    assert severity_to_strength(severity=2, action="drop") == 1.0
    assert severity_to_strength(severity=1, action="allowed") == 1.0


def test_severity_to_strength_scales_down_for_lower_severity():
    assert severity_to_strength(severity=2, action="allowed") == 0.6
    assert severity_to_strength(severity=3, action="allowed") == 0.3
    assert severity_to_strength(severity=None, action="allowed") == 0.25


def test_ingest_eve_alert_builds_evidence():
    detector = SignatureDetector()
    alert = {
        "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 2001219, "severity": 2, "action": "allowed"},
    }
    evidence = detector.ingestEveAlert(alert)

    assert evidence.source == Layer.L1_SIGNATURE
    assert evidence.kind == EvidenceType.SIGNATURE
    assert evidence.host_ip == "10.0.0.5"
    assert evidence.flow_id is None
    assert evidence.strength == 0.6
    assert evidence.signature_id == 2001219


def test_analyse_wraps_single_evidence_in_list():
    detector = SignatureDetector()
    alert = {"src_ip": "10.0.0.5", "alert": {"signature_id": 1, "severity": 1, "action": "drop"}}
    result = detector.analyse(alert)
    assert len(result) == 1
    assert result[0].strength == 1.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_signature_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.sigbridge.signature_detector'`

- [ ] **Step 3: Write `services/sigbridge/signature_detector.py`**

```python
"""FR-2.6: converts one Suricata eve.json alert into Evidence. severity_to_strength() implements
the drop/severity-1 -> 1.0 convention the decision-fusion phase's Algorithm 5.5 notes already
assume this component follows."""
from __future__ import annotations

from typing import Optional

from common.detector import Detector
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer, utc_now_iso

_SEVERITY_STRENGTH = {2: 0.6, 3: 0.3}
_DEFAULT_STRENGTH = 0.25


def severity_to_strength(severity: Optional[int], action: Optional[str]) -> float:
    if action == "drop" or severity == 1:
        return 1.0
    return _SEVERITY_STRENGTH.get(severity, _DEFAULT_STRENGTH)


class SignatureDetector(Detector):
    name = "sigbridge"

    def ingestEveAlert(self, alert: dict) -> Evidence:
        alert_block = alert.get("alert", {})
        severity = alert_block.get("severity")
        action = alert_block.get("action")
        return Evidence(
            source=Layer.L1_SIGNATURE,
            flow_id=None,
            host_ip=alert.get("src_ip", ""),
            kind=EvidenceType.SIGNATURE,
            strength=severity_to_strength(severity, action),
            weight=0.0,  # services/sigbridge/main.py fills this from risk.weight_signature
            signature_id=alert_block.get("signature_id"),
        )

    def analyse(self, item: dict) -> Optional[list]:
        return [self.ingestEveAlert(item)]

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_signature_detector.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/sigbridge/signature_detector.py tests/unit/test_signature_detector.py
git commit -m "feat: add SignatureDetector bridging Suricata alerts into Evidence"
```

---

## Task 16: sigbridge entry point (`services/sigbridge/main.py`)

**Files:**
- Create: `services/sigbridge/main.py`
- Test: `tests/unit/test_sigbridge_main.py`

**Interfaces:**
- Consumes: `services.sigbridge.eve_tailer.EveTailer` (Task 14),
  `services.sigbridge.signature_detector.SignatureDetector` (Task 15), `common.bus.{STREAM_EVIDENCE,
  STREAM_HEARTBEATS, EventBus}`, `common.bus_messages.{MessageType, encode_envelope}`,
  `common.config_loader.get`.
- Produces: `process_alerts(conn, bus: EventBus, detector: SignatureDetector, alerts: list[dict]) ->
  int` (the dependency-injected core — reads `risk.weight_signature` once, fills `.weight` on every
  `Evidence`, publishes onto `STREAM_EVIDENCE`, returns the count published);
  `publish_heartbeat(bus, detector) -> None`; `main() -> None` (real loop: `EveTailer.poll()` every
  second, `process_alerts()` on whatever it returns, heartbeat on its own timer — not unit tested
  directly, same precedent as the other two `main.py` entry points in this plan).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_sigbridge_main.py
import fakeredis

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.sigbridge.main import process_alerts, publish_heartbeat
from services.sigbridge.signature_detector import SignatureDetector


def test_process_alerts_fills_weight_and_publishes_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    detector = SignatureDetector()
    alerts = [
        {"src_ip": "10.0.0.5", "alert": {"signature_id": 1, "severity": 1, "action": "drop"}},
    ]

    published = process_alerts(conn, bus, detector, alerts)

    assert published == 1
    received = []
    bus.consume(
        STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["strength"] == 1.0
    assert envelope["payload"]["weight"] == 3.0  # risk.weight_signature default


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    detector = SignatureDetector()
    publish_heartbeat(bus, detector)

    received = []
    bus.consume(
        STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    assert decode_envelope(received[0])["payload"]["name"] == "sigbridge"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_sigbridge_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.sigbridge.main'`

- [ ] **Step 3: Write `services/sigbridge/main.py`**

```python
"""Entry point for the Suricata eve.json bridge. process_alerts() is the dependency-injected core
every test calls; main() wraps it in a real polling loop with a heartbeat tick."""
from __future__ import annotations

import os
import time

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from services.sigbridge.eve_tailer import EveTailer
from services.sigbridge.signature_detector import SignatureDetector


def process_alerts(conn, bus: EventBus, detector: SignatureDetector, alerts) -> int:
    weight = config_get(conn, "risk.weight_signature")
    published = 0
    for alert in alerts:
        ev = detector.ingestEveAlert(alert)
        ev.weight = weight
        bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
        published += 1
    return published


def publish_heartbeat(bus: EventBus, detector: SignatureDetector) -> None:
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, detector.heartbeat()))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    eve_path = os.environ.get("NIDPS_EVE_JSON_PATH", "/var/log/suricata/eve.json")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    tailer = EveTailer(eve_path)
    detector = SignatureDetector()

    last_heartbeat = 0.0
    while True:
        alerts = tailer.poll()
        if alerts:
            process_alerts(conn, bus, detector, alerts)
        now = time.time()
        heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
        if now - last_heartbeat >= heartbeat_interval:
            publish_heartbeat(bus, detector)
            last_heartbeat = now
        time.sleep(1.0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_sigbridge_main.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add services/sigbridge/main.py tests/unit/test_sigbridge_main.py
git commit -m "feat: add sigbridge service entry point"
```

---

## Task 17: `CalibrationState` and Algorithm 5.4 (`services/mlscorer/calibration.py`)

**Files:**
- Create: `services/mlscorer/__init__.py`
- Create: `services/mlscorer/calibration.py`
- Test: `tests/unit/test_calibration.py`

**Interfaces:**
- Consumes: `common.schemas.utc_now_iso` (Phase 1), `common.config_loader.get` (Phase 1),
  `services.flowextract.features.FEATURE_NAMES` (Task 5, for the `total_fwd_bytes` index used to
  compute `u_max`).
- Produces: `ANOMALY_TAU_GLOBAL_BOOTSTRAP: float = 0.6` (used only until a real trained model sets a
  global threshold — see Global Constraints' bootstrap note); `CalibrationState` dataclass (attrs
  `threshold, global_threshold, computed_at: str, sample_count: int, u_max: Optional[int] = None` —
  matches the UML's `threshold, globalThreshold, computedAt, sampleCount`); method
  `recalibrate(scores: list[float], percentile: float, min_samples: int, max_shift: float) ->
  CalibrationState` (Algorithm 5.4 lines 6-11, pure — the caller has already filtered `scores` per
  lines 2-5); module function `recalibrate_if_due(conn, score_fn: Callable[[list[float]], float],
  model_id: int, current_state: CalibrationState, window_start_iso: str, window_end_iso: str,
  now_iso: Optional[str] = None) -> CalibrationState` (the DB-aware wrapper: checks
  `anomaly.recalibration_interval_days` against `current_state.computed_at`; if due, gathers every
  `flow_record` in the window **excluding** flows with an `L1`-layer `evidence` row or a host with an
  `ACTIVE` `block_entry` row — Algorithm 5.4 lines 2-5 — scores each via `score_fn`, computes `u_max`
  as the `exfil.u_max_percentile`-th percentile of those flows' `total_fwd_bytes` feature, writes one
  new `calibration_state` row, and returns the new `CalibrationState`; returns `current_state`
  unchanged, by identity, when not yet due). `services/mlscorer/anomaly_service.py` (Task 21) calls
  `recalibrate_if_due()` once per its own periodic tick, passing `AnomalyDetector.score` (Task 18) as
  `score_fn`. FR-13.2 scope note: this task implements the recalibration *logic*; actual weekly
  cron-style scheduling (a systemd timer calling into this periodically) is a later, separate phase.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_calibration.py
import json
import math

from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.persistence import upsert_host
from services.mlscorer.calibration import CalibrationState, recalibrate_if_due

_FWD_BYTES_IDX = FEATURE_NAMES.index("total_fwd_bytes")


def test_recalibrate_falls_back_to_global_when_too_few_samples():
    state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    new_state = state.recalibrate([0.1, 0.2, 0.3], percentile=99.5, min_samples=10, max_shift=0.15)

    assert new_state.threshold == 0.6
    assert new_state.sample_count == 3


def test_recalibrate_clips_local_percentile_to_max_shift():
    state = CalibrationState(
        threshold=0.5, global_threshold=0.5, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    new_state = state.recalibrate([0.95] * 50, percentile=99.5, min_samples=10, max_shift=0.15)

    assert math.isclose(new_state.threshold, 0.65)


def _insert_flow(conn, host_id: int, start_time: str, fwd_bytes: float) -> int:
    values = [0.0] * len(FEATURE_NAMES)
    values[_FWD_BYTES_IDX] = fwd_bytes
    cursor = conn.execute(
        """INSERT INTO flow_record (host_id, src_ip, dst_ip, src_port, dst_port, protocol,
               start_time, end_time, segment_no, features, extractor_version)
           VALUES (?, '10.0.0.5', '1.2.3.4', 1, 2, 'TCP', ?, ?, 0, ?, 'dev')""",
        (host_id, start_time, start_time, json.dumps(values)),
    )
    conn.commit()
    return cursor.lastrowid


def _insert_model_package(conn) -> int:
    cursor = conn.execute(
        """INSERT INTO model_package (model_type, version, file_path, feature_list_hash,
               extractor_version, is_active)
           VALUES ('IFOREST', 'dev', 'dev', 'dev', 'dev', 1)"""
    )
    conn.commit()
    return cursor.lastrowid


def test_recalibrate_if_due_excludes_alerted_and_blocked_flows_and_writes_row():
    conn = connect(":memory:")
    seed_defaults(conn)
    update(conn, "anomaly.calibration_min_samples", 1)
    model_id = _insert_model_package(conn)
    host_id = upsert_host(conn, "10.0.0.5")
    other_host_id = upsert_host(conn, "10.0.0.9")

    eligible_flow_id = _insert_flow(conn, host_id, "2026-01-05T00:00:00.000000Z", 1000.0)
    alerted_flow_id = _insert_flow(conn, host_id, "2026-01-05T00:00:01.000000Z", 5000.0)
    blocked_flow_id = _insert_flow(conn, other_host_id, "2026-01-05T00:00:02.000000Z", 9000.0)

    conn.execute(
        "INSERT INTO evidence (flow_id, host_id, layer, evidence_type, weight) "
        "VALUES (?, ?, 'L1', 'SIGNATURE', 1.0)",
        (alerted_flow_id, host_id),
    )
    conn.execute(
        "INSERT INTO verdict (flow_id, host_id, decision, layers, explanation) "
        "VALUES (?, ?, 'BLOCK', '[]', 'x')",
        (blocked_flow_id, other_host_id),
    )
    verdict_id = conn.execute(
        "SELECT verdict_id FROM verdict WHERE flow_id = ?", (blocked_flow_id,)
    ).fetchone()[0]
    conn.execute(
        """INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time,
               expires_at, status)
           VALUES (?, ?, 1, 300, '2026-01-05T00:00:02.000000Z', '2026-01-05T00:05:02.000000Z', 'ACTIVE')""",
        (other_host_id, verdict_id),
    )
    conn.commit()

    current_state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2020-01-01T00:00:00.000000Z", sample_count=0
    )
    scored = []

    def score_fn(values):
        scored.append(values)
        return 0.9

    new_state = recalibrate_if_due(
        conn, score_fn, model_id, current_state,
        window_start_iso="2026-01-01T00:00:00.000000Z", window_end_iso="2026-01-10T00:00:00.000000Z",
        now_iso="2026-01-10T00:00:00.000000Z",
    )

    assert new_state.sample_count == 1  # only the eligible flow
    assert len(scored) == 1
    assert new_state.threshold == 0.75  # local percentile 0.9 clipped to [0.45, 0.75]
    assert new_state.u_max == 1000
    assert conn.execute("SELECT COUNT(*) FROM calibration_state").fetchone()[0] == 1


def test_recalibrate_if_due_returns_unchanged_state_when_not_due():
    conn = connect(":memory:")
    seed_defaults(conn)
    model_id = _insert_model_package(conn)
    current_state = CalibrationState(
        threshold=0.6, global_threshold=0.6, computed_at="2026-01-09T00:00:00.000000Z", sample_count=5
    )

    result = recalibrate_if_due(
        conn, lambda v: 0.5, model_id, current_state,
        window_start_iso="2026-01-01T00:00:00.000000Z", window_end_iso="2026-01-10T00:00:00.000000Z",
        now_iso="2026-01-10T00:00:00.000000Z",
    )

    assert result is current_state
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_calibration.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer'`

- [ ] **Step 3: Create package marker and write `services/mlscorer/calibration.py`**

`services/mlscorer/__init__.py`:
```python
```

`services/mlscorer/calibration.py`:
```python
"""Algorithm 5.4: per-network anomaly threshold calibration. CalibrationState.recalibrate() is
the pure math (lines 6-11) given an already-filtered score sample. recalibrate_if_due() is the
DB-aware wrapper that performs lines 2-5's filtering, computes u_max from the same local sample
(a documented extension -- see Global Constraints), and writes the new calibration_state row.
FR-13.2 scope note: this implements the recalibration logic only; a later systemd-timer phase
calls recalibrate_if_due() on a weekly schedule."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from common import config_loader
from common.schemas import utc_now_iso
from services.flowextract.features import FEATURE_NAMES

ANOMALY_TAU_GLOBAL_BOOTSTRAP = 0.6
_FWD_BYTES_IDX = FEATURE_NAMES.index("total_fwd_bytes")


def _percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return ordered[int(k)]
    return ordered[int(f)] * (c - k) + ordered[int(c)] * (k - f)


def _is_due(last_computed_at: str, interval_days: int, now_iso: str) -> bool:
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    last = datetime.strptime(last_computed_at, fmt).replace(tzinfo=timezone.utc)
    now = datetime.strptime(now_iso, fmt).replace(tzinfo=timezone.utc)
    return (now - last).days >= interval_days


@dataclass
class CalibrationState:
    threshold: float
    global_threshold: float
    computed_at: str
    sample_count: int
    u_max: Optional[int] = None

    def recalibrate(
        self, scores: list, percentile: float, min_samples: int, max_shift: float
    ) -> "CalibrationState":
        if len(scores) < min_samples:
            new_threshold = self.global_threshold
        else:
            local = _percentile(scores, percentile)
            new_threshold = min(
                max(local, self.global_threshold - max_shift), self.global_threshold + max_shift
            )
        return CalibrationState(
            threshold=new_threshold,
            global_threshold=self.global_threshold,
            computed_at=utc_now_iso(),
            sample_count=len(scores),
            u_max=self.u_max,
        )


def recalibrate_if_due(
    conn,
    score_fn: Callable,
    model_id: int,
    current_state: CalibrationState,
    window_start_iso: str,
    window_end_iso: str,
    now_iso: Optional[str] = None,
) -> CalibrationState:
    now_iso = now_iso or utc_now_iso()
    interval_days = config_loader.get(conn, "anomaly.recalibration_interval_days")
    if not _is_due(current_state.computed_at, interval_days, now_iso):
        return current_state

    percentile = config_loader.get(conn, "anomaly.calibration_percentile")
    min_samples = config_loader.get(conn, "anomaly.calibration_min_samples")
    max_shift = config_loader.get(conn, "anomaly.calibration_max_shift")
    u_max_percentile = config_loader.get(conn, "exfil.u_max_percentile")

    rows = conn.execute(
        "SELECT flow_id, host_id, features FROM flow_record WHERE start_time >= ? AND start_time < ?",
        (window_start_iso, window_end_iso),
    ).fetchall()
    alerted_flow_ids = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT flow_id FROM evidence WHERE layer = 'L1' AND flow_id IS NOT NULL"
        ).fetchall()
    }
    blocked_host_ids = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT host_id FROM block_entry WHERE status = 'ACTIVE'"
        ).fetchall()
    }

    scores = []
    segment_bytes = []
    for flow_id, host_id, features_json in rows:
        if flow_id in alerted_flow_ids or host_id in blocked_host_ids:
            continue
        values = json.loads(features_json)
        scores.append(score_fn(values))
        segment_bytes.append(values[_FWD_BYTES_IDX])

    u_max = int(_percentile(segment_bytes, u_max_percentile)) if segment_bytes else current_state.u_max
    new_state = current_state.recalibrate(scores, percentile, min_samples, max_shift)
    new_state.u_max = u_max

    conn.execute(
        """INSERT INTO calibration_state
               (model_id, tau, tau_global, percentile, sample_count, u_max, window_start,
                window_end, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            model_id, new_state.threshold, new_state.global_threshold, percentile,
            new_state.sample_count, u_max, window_start_iso, window_end_iso, new_state.computed_at,
        ),
    )
    conn.commit()
    return new_state
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_calibration.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/__init__.py services/mlscorer/calibration.py tests/unit/test_calibration.py
git commit -m "feat: add CalibrationState implementing threshold calibration (Algorithm 5.4)"
```

---

## Task 18: `AnomalyDetector` (Eq 5.2-5.3, FR-4.1-4.4) (`services/mlscorer/anomaly.py`)

**Files:**
- Create: `services/mlscorer/anomaly.py`
- Test: `tests/unit/test_anomaly_detector.py`

**Interfaces:**
- Consumes: `common.detector.Detector`, `common.schemas.{ComponentHealth, Evidence, EvidenceType,
  FEATURE_COUNT, FlowFeatures, HealthState, Layer, SCHEMA_VERSION, utc_now_iso}` (Phase 1),
  `services.mlscorer.calibration.CalibrationState` (Task 17), `sklearn.ensemble.IsolationForest`.
- Produces: `FeatureSchemaMismatch(ValueError)` exception; `fit_bootstrap_model(X, n_estimators=100,
  max_samples=256, random_state=42) -> IsolationForest` (test/bootstrap helper per Global
  Constraints); `load_active_model(conn, models_dir: str = "") -> tuple[int, IsolationForest]`
  (production loader — not exercised by any test here since no training phase exists yet to produce
  a real file); `AnomalyDetector(Detector)` — attr `model: IsolationForest` (matches UML);
  constructor `(model, calibration: CalibrationState, model_id: Optional[int] = None)`; method
  `score(features: FlowFeatures) -> float` (FR-4.1: raises `FeatureSchemaMismatch` if
  `features.validate()` fails; FR-4.2: maps sklearn's `score_samples()` to the paper's `[0,1]`,
  "higher = more anomalous" convention via `-score_samples(X)`, clipped); method `analyse(item:
  tuple[str, Optional[str], FlowFeatures]) -> Optional[list[Evidence]]` (FR-4.3: `None` if
  `score <= calibration.threshold`, else one `ANOMALY` `Evidence` with `strength=score`); method
  `heartbeat() -> ComponentHealth`. `services/mlscorer/anomaly_service.py` (Task 21) constructs one
  `AnomalyDetector` per `calibration_state` refresh and calls `analyse()` once per `FLOW_READY`
  message.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_anomaly_detector.py
import statistics
import time

import numpy as np
import pytest

from common.schemas import FEATURE_COUNT, HealthState, FlowFeatures, SCHEMA_VERSION
from services.mlscorer.anomaly import AnomalyDetector, FeatureSchemaMismatch, fit_bootstrap_model
from services.mlscorer.calibration import CalibrationState


def _fitted_model():
    rng = np.random.RandomState(42)
    X = rng.normal(0, 1, (100, FEATURE_COUNT))
    return fit_bootstrap_model(X, n_estimators=50, max_samples=64, random_state=42)


def _calibration(threshold: float) -> CalibrationState:
    return CalibrationState(threshold=threshold, global_threshold=threshold, computed_at="x", sample_count=0)


def test_score_is_bounded_and_higher_for_outliers():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))

    normal = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)
    outlier = FlowFeatures(schema_version=SCHEMA_VERSION, values=[50.0] * FEATURE_COUNT)

    normal_score = detector.score(normal)
    outlier_score = detector.score(outlier)

    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= outlier_score <= 1.0
    assert outlier_score > normal_score


def test_score_raises_on_wrong_length_feature_vector():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    bad = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * 10)

    with pytest.raises(FeatureSchemaMismatch):
        detector.score(bad)


def test_analyse_returns_none_below_threshold_and_evidence_above():
    calibration = _calibration(0.99)
    detector = AnomalyDetector(model=_fitted_model(), calibration=calibration, model_id=7)
    normal = FlowFeatures(schema_version=SCHEMA_VERSION, values=[0.0] * FEATURE_COUNT)

    assert detector.analyse(("10.0.0.5", "1", normal)) is None

    calibration.threshold = 0.0
    result = detector.analyse(("10.0.0.5", "1", normal))
    assert len(result) == 1
    assert result[0].kind.value == "ANOMALY"
    assert result[0].model_id == 7
    assert result[0].host_ip == "10.0.0.5"


def test_heartbeat_reports_normal():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    assert detector.heartbeat().state == HealthState.NORMAL


def test_score_meets_nfr3_median_latency_budget():
    detector = AnomalyDetector(model=_fitted_model(), calibration=_calibration(0.6))
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=[1.0] * FEATURE_COUNT)

    durations_ms = []
    for _ in range(200):
        start = time.perf_counter()
        detector.score(features)
        durations_ms.append((time.perf_counter() - start) * 1000.0)

    assert statistics.median(durations_ms) <= 10.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/pytest tests/unit/test_anomaly_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer.anomaly'` (and `numpy`
may need installing — see Step 3a).

- [ ] **Step 3a: Add `numpy` and `joblib` to `requirements.txt`**

Append to `requirements.txt`:
```
numpy>=1.24,<2.0
joblib>=1.3,<2.0
```

Run: `.venv/Scripts/pip install -r requirements.txt`

- [ ] **Step 3b: Write `services/mlscorer/anomaly.py`**

```python
"""Eq 5.2-5.3, FR-4.1-4.4: Isolation Forest anomaly scoring. _score_to_paper_convention() is the
one place sklearn's sign flip is undone -- score_samples() is documented by scikit-learn as "the
opposite of the anomaly score defined in the original paper" (the same paper Eq 5.2-5.3 comes
from), so s(x,psi) = -score_samples(x), clipped to [0,1] to guard floating-point edge cases."""
from __future__ import annotations

from typing import Optional

from sklearn.ensemble import IsolationForest

from common.detector import Detector
from common.schemas import (
    ComponentHealth,
    Evidence,
    EvidenceType,
    FEATURE_COUNT,
    FlowFeatures,
    HealthState,
    Layer,
    SCHEMA_VERSION,
    utc_now_iso,
)
from services.mlscorer.calibration import CalibrationState


class FeatureSchemaMismatch(ValueError):
    pass


def _score_to_paper_convention(model: IsolationForest, values: list) -> float:
    raw = model.score_samples([values])[0]
    return max(0.0, min(1.0, -raw))


def fit_bootstrap_model(
    X, n_estimators: int = 100, max_samples: int = 256, random_state: int = 42
) -> IsolationForest:
    """Fits a local IsolationForest on sample data for tests/bootstrapping. Production model
    loading goes through load_active_model() once the (separate, later) training phase exists."""
    return IsolationForest(
        n_estimators=n_estimators, max_samples=max_samples, random_state=random_state
    ).fit(X)


def load_active_model(conn, models_dir: str = ""):
    import joblib

    row = conn.execute(
        """SELECT model_id, file_path FROM model_package
           WHERE model_type = 'IFOREST' AND is_active = 1
           ORDER BY deployed_at DESC LIMIT 1"""
    ).fetchone()
    if row is None:
        raise LookupError("no active IFOREST model_package row found")
    model_id, file_path = row
    return model_id, joblib.load(file_path)


class AnomalyDetector(Detector):
    name = "mlscorer-anomaly"

    def __init__(
        self, model: IsolationForest, calibration: CalibrationState, model_id: Optional[int] = None
    ) -> None:
        self.model = model
        self.calibration = calibration
        self.model_id = model_id

    def score(self, features: FlowFeatures) -> float:
        if not features.validate():
            raise FeatureSchemaMismatch(
                f"expected {FEATURE_COUNT} floats under schema {SCHEMA_VERSION!r}, got "
                f"{len(features.values)} under {features.schema_version!r}"
            )
        return _score_to_paper_convention(self.model, features.values)

    def analyse(self, item) -> Optional[list]:
        host_ip, flow_id, features = item
        try:
            score = self.score(features)
        except FeatureSchemaMismatch:
            return None
        if score <= self.calibration.threshold:
            return None
        return [
            Evidence(
                source=Layer.L2_ANOMALY,
                flow_id=flow_id,
                host_ip=host_ip,
                kind=EvidenceType.ANOMALY,
                strength=score,
                weight=0.0,  # services/mlscorer/anomaly_service.py fills this from risk.weight_anomaly
                model_id=self.model_id,
            )
        ]

    def heartbeat(self) -> ComponentHealth:
        return ComponentHealth(
            name=self.name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/pytest tests/unit/test_anomaly_detector.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add requirements.txt services/mlscorer/anomaly.py tests/unit/test_anomaly_detector.py
git commit -m "feat: add AnomalyDetector implementing Isolation Forest scoring (Eq 5.2-5.3)"
```

---
