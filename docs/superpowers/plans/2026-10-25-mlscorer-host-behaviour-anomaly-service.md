# NIDPS Host Behaviour Tracking & Layer-2 Anomaly Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Phase 2 of the NIDPS roadmap by building the two components its own plan described but never wrote: `services/mlscorer/host_behaviour.py` (`HostBehaviourTracker`, implementing FR-4.5/4.6 — per-host exfiltration tracking and C2 beaconing detection) and `services/mlscorer/anomaly_service.py` (the entry point that actually consumes `STREAM_FLOWS`, scores each flow with the already-built `AnomalyDetector`, runs it through `HostBehaviourTracker`, and publishes any resulting `Evidence` onto `STREAM_EVIDENCE`). Without this plan, Layer-2 anomaly scoring has no running service — `AnomalyDetector` and `CalibrationState` exist and are tested in isolation, but nothing wires them to live traffic.

**Architecture:** `HostBehaviourTracker` is a pure, DB-free, in-memory object (same style as `ArpMonitor`) composed of two independent trackers: `ExfiltrationTracker` (Eq 5.4 — per-host EWMA baseline of outbound bytes per time bucket, plus a fast path on individual active-timeout segments) and `BeaconTracker` (Eq 5.5 — coefficient-of-variation periodicity detection on groups keyed by host+destination+JA3). Both take a plain `FlowObservation` value object and return `Evidence` with `weight=0.0`, following this whole plan's weight-contract convention. `main.py`'s `anomaly_service.py` is the only module that touches both the database (to re-read `flow_record.features`, run the "never contacted this destination before" check, and load/refresh calibration) and the event bus (to consume `STREAM_FLOWS` under consumer group `"layer2-anomaly"` and publish `Evidence` onto `STREAM_EVIDENCE`) — `HostBehaviourTracker` itself never imports `sqlite3` or `common.bus`.

**Tech Stack:** Python 3.11+, stdlib `math`/`dataclasses`/`collections`, `pytest`. No new third-party dependencies — everything this plan needs (`scikit-learn`, `redis`/`fakeredis`, `sqlite3`) is already installed from the parent plan.

**Spec:** `nidps_report/chapters/ch1to4.tex` (FR-4.5, FR-4.6) and `nidps_report/chapters/ch5.tex` §5.5.3 "Data Exfiltration Score" (Eq. `eq:ewma`) and §5.5.4 "C2 Beaconing Score" (Eq. `eq:cv`); `docs/superpowers/plans/2026-10-10-02-flow-extraction-arp-anomaly.md`(the parent plan — already executed, merged to `master` — whose Global Constraints, config keys, schema, and Tasks 1-18 this plan builds directly on top of, and whose own text names these two components without ever writing them).

## Global Constraints

- Python 3.11+, same conventions as the parent plan: `common.schemas.utc_now_iso()` is the only function that stamps the current wall-clock moment; packet/flow timing uses the raw POSIX epoch floats already present on `EmittedFlow`/`flow_record.start_time`/`end_time`.
- **No new database tables and no new columns.** This plan owns no table. `HostBehaviourTracker`'s bucket/group state is process-lifetime, in-memory, and reset on service restart — the same acceptable precedent `ArpMonitor`'s flood-window state and JA3-rarity tracking already set in the parent plan. The one piece of durable state this plan reads is `calibration_state`, via the parent plan's `services/mlscorer/calibration.py::load_calibration_state()` (already built).
- **Config keys consumed (already defined by the parent plan's Phase 1 foundation, read via** `common.config_loader.get()`**, never hardcoded):** `exfil.ewma_alpha` (0.3), `exfil.bucket_seconds`(60), `exfil.k_std` (4.0), `exfil.u_max_percentile` (99.9, consumed indirectly via `calibration_state.u_max`), `beacon.min_connections` (5), `beacon.cv_threshold` (0.15), `risk.weight_exfil` (2.0), `risk.weight_beacon` (2.5), `risk.weight_anomaly` (2.0), `anomaly.calibration_window_hours` (48), `watchdog.heartbeat_interval_s` (1.0).
- **Three numeric decisions the spec leaves unquantified, fixed here the same way the parent plan fixed** `RARE_JA3_HOST_THRESHOLD` **and the ARP flood constants — as documented module-level constants, not** `CONFIG_SETTING` **rows, since they aren't in the given config key list:**
  - `EXFIL_RATIO_THRESHOLD = 3.0` in `host_behaviour.py` — §5.5.3 says a bucket is flagged only when the magnitude check holds "and the outbound-to-inbound byte ratio of the host's flows is also unusually high," without a number. A bucket's forward bytes must be at least 3× its backward bytes (`fwd_total / max(bwd_total, 1.0) >= 3.0`) to count as "unusually high" — chosen so ordinary two-way traffic (video calls, which the spec explicitly calls out as the case this guards against) with a roughly 1:1 to 2:1 ratio never qualifies, while a one-sided upload does.
  - `BYTES_CV_THRESHOLD` for the beacon score's "low variance in bytes per connection" signal reuses the existing `beacon.cv_threshold` config key (0.15) rather than inventing a second config key — the spec names this as a separate signal from timing CV but gives it no number of its own, and reusing the one CV threshold the project already has is the smallest addition that satisfies "low variance" without adding a tunable nothing else needs yet.
  - `RARE_JA3_HOST_THRESHOLD = 2` — copied verbatim from the parent plan's own Global Constraints (it already fixed this value for Eq 5.5's "rare JA3 fingerprint" signal; this plan reuses the same constant rather than redefining it, since both live in the same `services/mlscorer/`package and must agree).
- **Beacon group key:** `(host_ip, dst_key, ja3)` where `dst_key` is `sni` if the flow has one, else `dst_ip` — matching §5.5.4's "destination IP or TLS server name, JA3" literally. A flow with no JA3 (plain non-TLS traffic) still forms a group keyed by `ja3=None`; such a group can never satisfy the "rare JA3" signal (there is no fingerprint to be rare), so it can never produce beacon evidence — this falls out of the rarity check naturally and needs no special case.
- **Beacon evidence re-fires, it does not fire once per group.** Every connection added to an already-periodic group re-evaluates all three signals and can produce another `Evidence` if they still hold — this matches the parent plan's host-risk-score design (steady weak evidence accumulates; a single stray signal does not), and avoids this plan inventing its own de-duplication state when a later, separate decision-fusion phase already owns that accumulation.
- **"Never contacted this destination before" (FR-4.5's fast-path novelty check) is answered by a direct** `flow_record` **query, not an unbounded in-memory per-host destination set.** The parent plan's own final review flagged exactly this failure mode (I7: an unbounded per-key dict that only grows) as a Critical-adjacent defect in `ArpMonitor`; this plan avoids repeating it by querying `SELECT 1 FROM flow_record WHERE host_id = ? AND dst_ip = ? AND flow_id != ? LIMIT 1`instead of keeping a growing in-process set. This keeps `HostBehaviourTracker` itself DB-free: `anomaly_service.py` (the one DB-aware module) runs this query and passes the boolean result in on `FlowObservation.is_new_destination` — the tracker never sees a connection or a host_id.
- **Evidence weight contract (same as every detector in the parent plan):** `ExfiltrationTracker`and `BeaconTracker` both set `Evidence.weight = 0.0` and let `anomaly_service.py` fill it from `risk.weight_exfil` / `risk.weight_beacon` respectively, immediately before publishing — exactly the pattern `services/arpmon/main.py::process_frames` and `services/sigbridge/main.py::process_alerts`already use.
- **Bootstrap model handling in** `anomaly_service.py`**:** no training phase exists yet to produce a real `model_package` row (the parent plan's own documented bootstrap gap). `main()` calls `load_active_model(conn)` at startup; if it raises `LookupError` (no active `IFOREST` row yet), `main()` logs a warning and runs with anomaly scoring disabled — `HostBehaviourTracker` still runs (exfiltration/beaconing need no model) and heartbeats still publish — retrying `load_active_model` once per `anomaly.recalibration_interval_days`-independent fixed interval (a simple 60-second retry, not config-driven, since this is a startup bootstrap concern, not a runtime tunable). This path is part of the untested `main()` wrapper, matching this whole plan family's established precedent of only unit-testing the dependency-injected core.

## Review Focus

- A beacon group with fewer than `beacon.min_connections` connections must not compute a coefficient of variation at all (division by a sample size that doesn't support one) — covered by Task 20's test that a group below the threshold produces no evidence and does not raise.
- A connection group whose mean inter-arrival time or mean bytes-per-connection is exactly zero (e.g. two connections at the same timestamp, or zero-byte connections) must not raise `ZeroDivisionError` computing `CV = σ/μ` — covered by Task 20.
- The very first bucket `ExfiltrationTracker` ever finalizes for a host has no established EWMA baseline yet (`initialized=False`) — it must update the baseline and skip the anomaly check entirely, never comparing against a zero-sample mean/variance — covered by Task 19.
- A flow whose backward byte count is exactly 0 must not raise `ZeroDivisionError` computing the outbound/inbound ratio for the exfiltration bucket check — covered by Task 19 (the `max(bwd_total, 1.0)` guard).
- The "never contacted this destination before" query must exclude the current flow's own row (it is itself a `flow_record` entry with that `host_id`/`dst_ip` pair by the time `anomaly_service.py` queries it) — otherwise every flow would appear to be a repeat visit to itself and the fast path would never fire. Covered by Task 22's test.

---

## File Structure

```
services/
  mlscorer/
    host_behaviour.py        # NEW: FlowObservation, ExfiltrationTracker, BeaconTracker,
                              #   HostBehaviourTracker (Eq 5.4-5.5, FR-4.5/4.6)
    anomaly_service.py       # NEW: entry point — consume STREAM_FLOWS (group "layer2-anomaly")
                              #   -> score with AnomalyDetector + HostBehaviourTracker -> publish
                              #   Evidence -> heartbeat
tests/
  unit/
    test_host_behaviour.py   # NEW
    test_anomaly_service.py  # NEW
```

---

## Task 19: `ExfiltrationTracker` (Eq 5.4, FR-4.5) (`services/mlscorer/host_behaviour.py` part 1)

**cker is a pure, DB-free, in-memory object (Files:**

- Create: `services/mlscorer/host_behaviour.py`
- Test: `tests/unit/test_host_behaviour.py`

**Interfaces:**

- [ ] 

- Consumes: `common.schemas.{ComponentHealth, Evidence, EvidenceType, Layer}` (already merged).
- Produces: `EXFIL_RATIO_THRESHOLD: float = 3.0`; `FlowObservation` dataclass (`host_ip: str, dst_ip: str, sni: Optional[str], ja3: Optional[str], fwd_bytes: float, bwd_bytes: float, end_time_epoch: float, is_partial: bool, is_new_destination: bool` — this is Task 21's shared value object, defined here since `ExfiltrationTracker` is its first consumer); `ExfiltrationTracker` class — constructor `(ewma_alpha: float, bucket_seconds: int, k_std: float, u_max: Optional[int])`; method `observe(obs: FlowObservation) -> list[Evidence]`. Task 20's `BeaconTracker` does not depend on this class; Task 21's `HostBehaviourTracker` composes both.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_host_behaviour.py
import math

from common.schemas import EvidenceType, Layer
from services.mlscorer.host_behaviour import ExfiltrationTracker, FlowObservation


def _obs(host_ip, dst_ip, fwd, bwd, end_time, is_partial=False, is_new_destination=False, sni=None, ja3=None):
    return FlowObservation(
        host_ip=host_ip, dst_ip=dst_ip, sni=sni, ja3=ja3, fwd_bytes=fwd, bwd_bytes=bwd,
        end_time_epoch=end_time, is_partial=is_partial, is_new_destination=is_new_destination,
    )


def test_first_bucket_finalize_has_no_baseline_and_never_flags():
    # alpha=0.5, bucket=60s, k_std=2.0, u_max disabled (fast path tested separately below).
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    # Bucket 0 (t=10): fwd=100, bwd=100. Bucket 1 (t=70) finalizes bucket 0 -- but there is no
    # established baseline yet, so no check runs no matter how large bucket 0 was.
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 10_000.0, 1.0, end_time=10.0)) == []
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 1.0, 1.0, end_time=70.0)) == []


def test_bucket_flags_only_when_magnitude_and_ratio_both_hold():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    # Establish a baseline across three one-flow-per-bucket buckets (100, 120, 130 fwd bytes,
    # all with a near-1:1 ratio so the ratio gate alone would never fire for them):
    #   bucket0 fwd=100,bwd=100 -> finalized by bucket1's arrival: no baseline yet, skip check.
    #     baseline becomes mean=50.0, var=5000.0 (alpha*100^2 off a mean of 0).
    #   bucket1 fwd=120,bwd=110 -> finalized by bucket2's arrival: mean=50,var=5000,std=70.71...
    #     threshold=50+2*70.71=191.4; b_t=120 < threshold -> no flag. New mean=85.0, var=4950.0.
    #   bucket2 fwd=130,bwd=120 -> finalized by bucket3's arrival: mean=85,var=4950,std=70.36...
    #     threshold=85+2*70.36=225.7; b_t=130 < threshold -> no flag. New mean=107.5, var=3487.5.
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.5", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000, bwd=50 (ratio=100, far over EXFIL_RATIO_THRESHOLD). Not yet finalized --
    # no evidence from THIS call; it just starts accumulating bucket3.
    assert tracker.observe(_obs("10.0.0.5", "1.2.3.4", 5000.0, 50.0, end_time=190.0)) == []
    # bucket4 arrival finalizes bucket3: mean=107.5, var=3487.5, std=59.055...
    #   threshold=107.5+2*59.055=225.6; b_t=5000 > threshold AND ratio=5000/50=100 >= 3.0 -> FLAG.
    evidence = tracker.observe(_obs("10.0.0.5", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].source == Layer.L2_ANOMALY
    assert evidence[0].host_ip == "10.0.0.5"
    assert evidence[0].weight == 0.0
    assert evidence[0].strength == 1.0


def test_bucket_does_not_flag_when_ratio_is_too_low_despite_large_magnitude():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000 (huge, would trip the magnitude check) but bwd=4000 too -- ratio=1.25,
    # well under EXFIL_RATIO_THRESHOLD=3.0 -- this is "normal" large two-way traffic.
    tracker.observe(_obs("10.0.0.9", "1.2.3.4", 5000.0, 4000.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.9", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert evidence == []


def test_zero_backward_bytes_does_not_raise_and_ratio_is_treated_as_maximal():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 100.0, 100.0, end_time=10.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 120.0, 110.0, end_time=70.0))
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 130.0, 120.0, end_time=130.0))
    # bucket3: fwd=5000, bwd=0 exactly -- must not raise ZeroDivisionError.
    tracker.observe(_obs("10.0.0.3", "1.2.3.4", 5000.0, 0.0, end_time=190.0))
    evidence = tracker.observe(_obs("10.0.0.3", "1.2.3.4", 10.0, 10.0, end_time=250.0))
    assert len(evidence) == 1


def test_fast_path_fires_only_on_partial_segment_over_umax_to_new_destination():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000)
    # Not partial -- no fast-path check regardless of size/destination.
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 5000.0, 10.0, end_time=10.0, is_partial=False, is_new_destination=True)) == []
    # Partial, over u_max, but NOT a new destination -- no fast-path evidence.
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 5000.0, 10.0, end_time=20.0, is_partial=True, is_new_destination=False)) == []
    # Partial, under u_max, new destination -- no fast-path evidence (not over the threshold).
    assert tracker.observe(_obs("10.0.0.7", "1.2.3.4", 500.0, 10.0, end_time=30.0, is_partial=True, is_new_destination=True)) == []
    # Partial, over u_max, new destination -- fires immediately, no bucket finalize needed.
    evidence = tracker.observe(_obs("10.0.0.7", "9.9.9.9", 5000.0, 10.0, end_time=40.0, is_partial=True, is_new_destination=True))
    assert len(evidence) == 1
    assert evidence[0].kind == EvidenceType.EXFIL
    assert evidence[0].strength == 1.0


def test_u_max_none_disables_fast_path_entirely():
    tracker = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    evidence = tracker.observe(_obs("10.0.0.8", "9.9.9.9", 1_000_000.0, 1.0, end_time=10.0, is_partial=True, is_new_destination=True))
    assert evidence == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v`Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer.host_behaviour'`

- [ ] **Step 3: Write** `services/mlscorer/host_behaviour.py` **(Task 19 portion)**

Implement `FlowObservation` as a plain `@dataclass` with exactly the fields listed in Interfaces above. Implement `ExfiltrationTracker` keeping one per-host state record (`current_bucket_idx: Optional[int]`, `current_fwd: float`, `current_bwd: float`, `ewma_mean: float`, `ewma_var: float`, `initialized: bool`) in a `dict[str, _ExfilState]` keyed by `host_ip`. `observe()`:

1. Runs the fast-path check first (`obs.is_partial and self._u_max is not None and obs.fwd_bytes > self._u_max and obs.is_new_destination` → append one `Evidence(source=Layer.L2_ANOMALY, flow_id=None, host_ip=obs.host_ip, kind=EvidenceType.EXFIL, strength=1.0, weight=0.0)` — `flow_id`is `None` here because `FlowObservation` deliberately carries no `flow_id`, matching this plan's DB-free-tracker design decision; `anomaly_service.py`, which already has the real `flow_id` from the bus message, is free to set it before publishing if desired, but the tracker itself has no way to know it).
2. Computes `bucket_idx = math.floor(obs.end_time_epoch / self._bucket_seconds)` and either starts tracking a new host, accumulates into the current bucket (same `bucket_idx`), or finalizes the previous bucket and starts a new one (different `bucket_idx`) using the exact arithmetic the two tests above hand-verify: `b_t = current_fwd`; if `initialized`, compute `std = math.sqrt(ewma_var)` and flag when `b_t > ewma_mean + k_std * std AND current_fwd / max(current_bwd, 1.0) >= EXFIL_RATIO_THRESHOLD`; then update `ewma_mean = alpha*b_t + (1-alpha)*ewma_mean`, \`ewma_var = alpha\*(b_t-ewma_mean_before_update)\*\*2
   - (1-alpha)\*ewma_var`(Eq`eq:ewma`— note the variance term uses the *pre-update* mean, exactly as the two hand-verified tests above compute it), set`initialized = True\`.
3. Returns the list of zero or one `Evidence` objects produced by whichever of the two checks fired (fast path and bucket-finalize are independent and could, in principle, both fire on the same call — that's fine, don't suppress one for the other).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v`Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/host_behaviour.py tests/unit/test_host_behaviour.py
git commit -m "feat: add ExfiltrationTracker implementing per-host EWMA exfil detection (Eq 5.4, FR-4.5)"
```

---

## Task 20: `BeaconTracker` (Eq 5.5, FR-4.6) (`services/mlscorer/host_behaviour.py` part 2)

**Files:**

- Modify: `services/mlscorer/host_behaviour.py`
- Test: `tests/unit/test_host_behaviour.py`

**Interfaces:**

- [ ] 

- Consumes: `services.mlscorer.host_behaviour.FlowObservation` (Task 19), `common.schemas.{Evidence, EvidenceType, Layer}`.
- Produces: `RARE_JA3_HOST_THRESHOLD: int = 2`; `BYTES_CV_THRESHOLD` (reuses the `cv_threshold`value passed into the constructor — see below, not a separate constant); `BeaconTracker` class — constructor `(min_connections: int, cv_threshold: float)`; method `observe(obs: FlowObservation) -> Optional[Evidence]` (singular, matching the UML-style "a group is reported" language in the spec — unlike `ExfiltrationTracker`, at most one beacon evidence item can result from a single observation, since one flow belongs to exactly one group). Task 21's `HostBehaviourTracker`calls this once per flow alongside `ExfiltrationTracker.observe()`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_host_behaviour.py`:

```python
from services.mlscorer.host_behaviour import BeaconTracker


def test_group_below_min_connections_never_computes_cv_or_flags():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    for t in (0.0, 10.0, 20.0, 30.0):  # only 4 connections, below min_connections=5
        result = tracker.observe(_obs("10.0.0.5", "1.2.3.4", 100.0, 100.0, end_time=t, ja3="abc"))
    assert result is None


def test_zero_mean_interval_or_bytes_does_not_raise():
    tracker = BeaconTracker(min_connections=2, cv_threshold=0.15)
    # Two connections at the exact same timestamp -- mean inter-arrival would be 0.
    tracker.observe(_obs("10.0.0.6", "1.2.3.4", 0.0, 0.0, end_time=5.0, ja3="abc"))
    result = tracker.observe(_obs("10.0.0.6", "1.2.3.4", 0.0, 0.0, end_time=5.0, ja3="abc"))
    assert result is None  # must not raise ZeroDivisionError


def test_periodic_group_with_rare_ja3_and_low_byte_variance_is_flagged():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    # 5 connections, 60s apart exactly (CV_time = 0.0), each carrying ~100 bytes total
    # (fwd+bwd), varying by at most 1 byte (CV_bytes well under 0.15), same rare JA3.
    result = None
    sizes = [100.0, 99.0, 100.0, 101.0, 100.0]
    for i, size in enumerate(sizes):
        result = tracker.observe(
            _obs("10.0.0.5", "9.9.9.9", size / 2, size / 2, end_time=i * 60.0, ja3="rare-fingerprint")
        )
    assert result is not None
    assert result.kind.value == "BEACON"
    assert result.host_ip == "10.0.0.5"
    assert result.weight == 0.0


def test_common_ja3_used_by_many_hosts_is_never_flagged_even_if_perfectly_periodic():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    # A common JA3 (e.g. a mainstream browser) seen from 3 distinct hosts -- not rare.
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        tracker.observe(_obs(host, "9.9.9.9", 50.0, 50.0, end_time=0.0, ja3="common-browser"))
    result = None
    for i in range(5):
        result = tracker.observe(
            _obs("10.0.0.1", "9.9.9.9", 50.0, 50.0, end_time=i * 60.0, ja3="common-browser")
        )
    assert result is None


def test_irregular_human_driven_timing_is_never_flagged():
    tracker = BeaconTracker(min_connections=5, cv_threshold=0.15)
    irregular_times = [0.0, 12.0, 95.0, 97.0, 400.0]  # high-variance gaps
    result = None
    for t in irregular_times:
        result = tracker.observe(_obs("10.0.0.5", "9.9.9.9", 100.0, 0.0, end_time=t, ja3="rare-fingerprint"))
    assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v -k Beacon`Expected: FAIL with `ImportError: cannot import name 'BeaconTracker'`

- [ ] **Step 3: Extend** `services/mlscorer/host_behaviour.py` **with** `BeaconTracker`

Keep two pieces of state: (a) per-group connection history, a `dict[tuple, list[tuple[float, float]]]` keyed by `(host_ip, dst_key, ja3)` mapping to a list of `(end_time_epoch, fwd_bytes + bwd_bytes)` pairs (`dst_key = obs.sni if obs.sni else obs.dst_ip`, per Global Constraints); (b) a network-wide `dict[str, set[str]]` mapping each JA3 string to the set of distinct `host_ip`s ever seen using it (this is the same rarity-tracking idea the parent plan's Global Constraints already named for `AnomalyDetector`'s sibling concerns — implement it fresh here since it did not exist anywhere yet). On `observe()`:

1. Record `obs.ja3` against `obs.host_ip` in the JA3→hosts map (skip if `obs.ja3 is None` — there is nothing to rate for a non-TLS flow).
2. Append `(obs.end_time_epoch, obs.fwd_bytes + obs.bwd_bytes)` to the group's history.
3. If `len(history) < self._min_connections`, return `None`.
4. Compute inter-arrival deltas from consecutive `end_time_epoch` values and the coefficient of variation (`CV = std/mean`, using **sample** standard deviation for consistency with this whole plan family's Welford convention, `ddof=1`); if the mean is `0.0`, treat CV as "not low" (return `None` for this signal rather than dividing by zero — a group whose connections are all at the same instant is not meaningfully periodic). Do the identical CV computation for the byte sizes.
5. Compute the JA3 rarity signal: `len(self._ja3_hosts.get(obs.ja3, set())) <= RARE_JA3_HOST_THRESHOLD` (skip entirely — not rare — if `obs.ja3 is None`).
6. Report `Evidence(source=Layer.L2_ANOMALY, flow_id=None, host_ip=obs.host_ip, kind=EvidenceType.BEACON, strength=1.0, weight=0.0)` only when timing CV `<= self._cv_threshold`AND bytes CV `<= self._cv_threshold` AND the JA3 is rare — otherwise `None`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v`Expected: 12 passed (7 from Task 19 + 5 new)

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/host_behaviour.py tests/unit/test_host_behaviour.py
git commit -m "feat: add BeaconTracker implementing C2 beaconing detection (Eq 5.5, FR-4.6)"
```

---

## Task 21: `HostBehaviourTracker` composition (`services/mlscorer/host_behaviour.py` part 3)

**Files:**

- Modify: `services/mlscorer/host_behaviour.py`
- Test: `tests/unit/test_host_behaviour.py`

**Interfaces:**

- [ ] 

- Consumes: `ExfiltrationTracker`, `BeaconTracker` (Tasks 19-20).
- Produces: `HostBehaviourTracker` class — constructor `(exfil: ExfiltrationTracker, beacon: BeaconTracker)`; method `observe(obs: FlowObservation) -> list[Evidence]` (concatenates `exfil.observe(obs)` with `[beacon.observe(obs)]` filtered of `None`). `services/mlscorer/ anomaly_service.py` (Task 22) constructs exactly one `HostBehaviourTracker` at startup and calls `observe()` once per `FLOW_READY` message, alongside its own `AnomalyDetector.analyse()` call.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_host_behaviour.py`:

```python
from services.mlscorer.host_behaviour import HostBehaviourTracker


def test_host_behaviour_tracker_combines_both_trackers_results():
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1000)
    beacon = BeaconTracker(min_connections=2, cv_threshold=0.15)
    combined = HostBehaviourTracker(exfil=exfil, beacon=beacon)

    # A fast-path-triggering observation: partial, over u_max, new destination. BeaconTracker
    # will see only 1 connection in this group (below its min_connections=2), so it contributes
    # nothing -- the combined result should have exactly the 1 EXFIL item.
    result = combined.observe(_obs(
        "10.0.0.5", "9.9.9.9", 5000.0, 10.0, end_time=10.0,
        is_partial=True, is_new_destination=True, ja3="rare-fp",
    ))
    assert len(result) == 1
    assert result[0].kind.value == "EXFIL"


def test_host_behaviour_tracker_returns_empty_list_when_neither_tracker_flags():
    exfil = ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None)
    beacon = BeaconTracker(min_connections=5, cv_threshold=0.15)
    combined = HostBehaviourTracker(exfil=exfil, beacon=beacon)
    assert combined.observe(_obs("10.0.0.5", "1.2.3.4", 10.0, 10.0, end_time=0.0)) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v -k HostBehaviourTracker`Expected: FAIL with `ImportError: cannot import name 'HostBehaviourTracker'`

- [ ] **Step 3: Add** `HostBehaviourTracker` **to** `services/mlscorer/host_behaviour.py`

A thin composition class — no new state of its own beyond holding references to the two trackers it was constructed with.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_host_behaviour.py -v`Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/host_behaviour.py tests/unit/test_host_behaviour.py
git commit -m "feat: add HostBehaviourTracker composing exfiltration and beacon detection"
```

---

## Task 22: `anomaly_service.py` entry point (`services/mlscorer/anomaly_service.py`)

**Files:**

- Create: `services/mlscorer/anomaly_service.py`
- Test: `tests/unit/test_anomaly_service.py`

**Interfaces:**

- [ ] 

- Consumes: `services.mlscorer.anomaly.{AnomalyDetector, FeatureSchemaMismatch, load_active_model}`(already merged), `services.mlscorer.calibration.{CalibrationState, load_calibration_state, recalibrate_if_due}` (already merged), `services.mlscorer.host_behaviour.{FlowObservation, HostBehaviourTracker}` (Tasks 19-21), `common.bus.{STREAM_FLOWS, STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus}`, `common.bus_messages.{MessageType, encode_envelope, decode_envelope}`, `common.config_loader.get`, `common.schemas.{FEATURE_COUNT, FlowFeatures, SCHEMA_VERSION, ComponentHealth, HealthState, utc_now_iso}`, `services.flowextract.features.FEATURE_NAMES` (for the `total_fwd_bytes`/`total_bwd_bytes`indices, same pattern `calibration.py` already uses).
- Produces: `is_new_destination(conn, host_id: int, dst_ip: str, flow_id: int) -> bool` (the one DB-aware helper this plan's Review Focus names — excludes the current `flow_id`'s own row from the check); `load_flow_observation(conn, flow_id: int, host_ip: str) -> Optional[tuple[FlowFeatures, FlowObservation]]` (re-reads one `flow_record` row by `flow_id`, returns `None` if the row is missing — defends against a stale/duplicate bus message — otherwise decodes `features` JSON into a `FlowFeatures`, and builds a `FlowObservation` from the row's `dst_ip`/`sni`/`ja3`/`segment_no == 0 is_partial`-style columns plus the `is_new_destination()` check); `process_flow_ready(conn, bus: EventBus, detector: Optional[AnomalyDetector], tracker: HostBehaviourTracker, body: str) -> int` (the dependency-injected core — decodes one `FLOW_READY` envelope, calls `load_flow_observation()`, runs `tracker.observe()` always and `detector.analyse()` only when `detector is not None`, fills `.weight` on every resulting `Evidence` from the matching `risk.weight_anomaly`/`risk.weight_exfil`/`risk.weight_beacon` key, publishes each onto `STREAM_EVIDENCE`, returns the count published); `publish_heartbeat(bus, component_name: str) -> None`; `main() -> None` (real loop: `bus.consume(STREAM_FLOWS, group="layer2-anomaly", ...)` per message, periodic `recalibrate_if_due` + model bootstrap retry + heartbeat — not unit tested directly, same precedent as every other `main.py` in this plan family).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_anomaly_service.py
import json

import fakeredis
import numpy as np

from common.bus import STREAM_EVIDENCE, STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.persistence import upsert_host, write_flow_record
from services.flowextract.flow_assembler import EmittedFlow
from services.mlscorer.anomaly import AnomalyDetector, fit_bootstrap_model
from services.mlscorer.calibration import CalibrationState
from services.mlscorer.host_behaviour import BeaconTracker, ExfiltrationTracker, HostBehaviourTracker
from services.mlscorer.anomaly_service import is_new_destination, process_flow_ready, publish_heartbeat
from common.schemas import FEATURE_COUNT, TLSFingerprint

_FWD_IDX = FEATURE_NAMES.index("total_fwd_bytes")
_BWD_IDX = FEATURE_NAMES.index("total_bwd_bytes")


def _write_flow(conn, host_id, dst_ip="1.2.3.4", fwd=10.0, bwd=10.0, ja3=None, sni=None):
    values = [0.0] * FEATURE_COUNT
    values[_FWD_IDX] = fwd
    values[_BWD_IDX] = bwd
    emitted = EmittedFlow(
        src_ip="10.0.0.5", dst_ip=dst_ip, src_port=1, dst_port=2, protocol="TCP",
        start_time=1_700_000_000.0, end_time=1_700_000_000.5, segment_no=0, is_partial=False,
        feature_values=values, tls=TLSFingerprint(ja3=ja3, server_name=sni),
    )
    return write_flow_record(conn, emitted, host_id)


def test_is_new_destination_excludes_the_flows_own_row():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9")
    # The only flow_record row for this (host_id, dst_ip) pair IS this flow itself.
    assert is_new_destination(conn, host_id, "9.9.9.9", flow_id) is True


def test_is_new_destination_false_when_a_different_flow_already_visited():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    _write_flow(conn, host_id, dst_ip="9.9.9.9")
    newer_flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9")
    assert is_new_destination(conn, host_id, "9.9.9.9", newer_flow_id) is False


def test_process_flow_ready_runs_host_behaviour_tracker_without_a_detector():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9", fwd=10.0, bwd=10.0)
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"})

    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    published = process_flow_ready(conn, bus, detector=None, tracker=tracker, body=body)
    assert published == 0  # nothing anomalous about one small flow to a fresh destination


def test_process_flow_ready_scores_with_detector_and_publishes_weighted_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id)

    rng = np.random.RandomState(42)
    model = fit_bootstrap_model(rng.normal(0, 1, (100, FEATURE_COUNT)), n_estimators=50, max_samples=64)
    # threshold=0.0 guarantees this flow's score exceeds it, so analyse() returns Evidence.
    calibration = CalibrationState(threshold=0.0, global_threshold=0.0, computed_at="x", sample_count=0)
    detector = AnomalyDetector(model=model, calibration=calibration, model_id=7)
    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"})

    published = process_flow_ready(conn, bus, detector, tracker, body)
    assert published == 1

    received = []
    bus.consume(STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    payload = decode_envelope(received[0])["payload"]
    assert payload["kind"] == "ANOMALY"
    assert payload["weight"] == 2.0  # risk.weight_anomaly default
    assert payload["model_id"] == 7


def test_process_flow_ready_returns_zero_for_missing_flow_record():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": 9999, "host_ip": "10.0.0.5"})
    assert process_flow_ready(conn, bus, detector=None, tracker=tracker, body=body) == 0


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    publish_heartbeat(bus, "mlscorer-anomaly")
    received = []
    bus.consume(STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["name"] == "mlscorer-anomaly"
    assert envelope["payload"]["state"] == "NORMAL"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_anomaly_service.py -v`Expected: FAIL with `ModuleNotFoundError: No module named 'services.mlscorer.anomaly_service'`

- [ ] **Step 3: Write** `services/mlscorer/anomaly_service.py`

- `is_new_destination()`: `conn.execute("SELECT 1 FROM flow_record WHERE host_id = ? AND dst_ip = ? AND flow_id != ? LIMIT 1", (host_id, dst_ip, flow_id)).fetchone() is None`.
- `load_flow_observation()`: `SELECT host_id, dst_ip, sni, ja3, segment_no, features FROM flow_record WHERE flow_id = ?`; return `None` if no row. Decode `features` via `json.loads`, build `FlowFeatures(schema_version=SCHEMA_VERSION, values=values)`. Read `total_fwd_bytes`/ `total_bwd_bytes` out of `values` by `FEATURE_NAMES.index(...)` (same pattern `calibration.py::_FWD_BYTES_IDX` already uses). `is_partial` is not itself a `flow_record`column (the parent plan never persisted it — a known, already-documented minor gap); treat `segment_no > 0` as a reasonable proxy for "this is a later segment of an ongoing flow, so it is plausibly still open" for the purposes of `FlowObservation.is_partial` — document this approximation in a one-line comment, it is the best available signal without a schema change this plan is not authorized to make. Call `is_new_destination()` for the `is_new_destination`field.
- `process_flow_ready()`: `decode_envelope(body)`, extract `flow_id`/`host_ip` from the payload, call `load_flow_observation()` — return `0` immediately if it returns `None`. Call `tracker.observe(obs)` unconditionally; call `detector.analyse((host_ip, flow_id, features))` only if `detector is not None`, catching nothing extra (the method already returns `None` on `FeatureSchemaMismatch` internally). For every `Evidence` produced by either call, look up its weight by `kind` (`EvidenceType.ANOMALY → "risk.weight_anomaly"`, `EvidenceType.EXFIL → "risk.weight_exfil"`, `EvidenceType.BEACON → "risk.weight_beacon"` — a small `_WEIGHT_CONFIG_KEY` dict, matching the parent plan's own established per-service-owns-its-copy precedent), set `.weight`, publish via `bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))`, and return the total count.
- `publish_heartbeat()`: identical shape to every other service's version in this plan family.
- `main()`: `bus.consume(STREAM_FLOWS, group="layer2-anomaly", consumer=<hostname or fixed id>, handler=lambda body: process_flow_ready(conn, bus, detector, tracker, body), block_ms=1000)` in a loop; construct `tracker` once from `CachedConfig`-read values at startup (reuse `services.flowextract.config_cache.CachedConfig` — importing a sibling phase's tiny dependency-free utility across a package boundary is fine here since neither module imports the other's business logic, only this one small class; do not create a third duplicate copy for a two-line startup read); attempt `load_active_model(conn)` + `load_calibration_state(conn, model_id)` to construct `detector`, falling back to `detector = None` on `LookupError` per the Global Constraints' bootstrap-handling note, retried every 60 seconds; call `recalibrate_if_due()` once per `anomaly.calibration_window_hours`-derived window on a periodic tick and swap `detector.calibration` if the returned state is a different object; heartbeat on `watchdog.heartbeat_interval_s`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_anomaly_service.py -v`Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add services/mlscorer/anomaly_service.py tests/unit/test_anomaly_service.py
git commit -m "feat: add anomaly_service entry point wiring AnomalyDetector and HostBehaviourTracker to the bus"
```

---

## Self-review notes (for the plan author, not a task to execute)

- **Spec coverage:** FR-4.5 (exfiltration EWMA + fast path) → Task 19; FR-4.6 (beaconing CV + rarity) → Task 20; "the system shall... flag it" for both → the composition and bus-wiring in Tasks 21-22, which is what makes either flag reach `STREAM_EVIDENCE` at all. Eq `eq:ewma` and Eq `eq:cv` are each implemented at exactly one call site (`ExfiltrationTracker.observe`, `BeaconTracker.observe` respectively) — no module recomputes either formula.
- **Placeholder scan:** none found — every task has complete literal test code with hand-verified expected values (Task 19's EWMA arithmetic, Task 20's CV cases) or a fully specified algorithm description (Task 19 Step 3, Task 20 Step 3, Task 22 Step 3) with no "TBD"/"handle edge cases" language.
- **Type consistency:** `FlowObservation` is defined once (Task 19) and used identically by name in Tasks 20-22; `HostBehaviourTracker.observe()`'s return type (`list[Evidence]`) matches what Task 22's `process_flow_ready()` expects to iterate; `Evidence.weight` starts at `0.0` in every constructor call across Tasks 19-20 and is filled exactly once, in Task 22, matching the parent plan's contract.
- **Review Focus:** all five items above are each pinned by a named test in Tasks 19, 20, or 22.