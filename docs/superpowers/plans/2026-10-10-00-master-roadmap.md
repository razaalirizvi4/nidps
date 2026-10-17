# NIDPS Implementation Roadmap

> **For agentic workers:** This is an index, not an executable plan. Each phase links to its own
> plan file under `docs/superpowers/plans/`. Execute each phase's plan with
> superpowers:subagent-driven-development (recommended) or superpowers:executing-plans, in the order
> below — later phases consume types, schemas, and event-bus messages defined by earlier ones.

**Source spec:** `E:\nidps_report\F26-030.pdf` — "NIDPS: Network Intrusion Detection and Prevention
System" (FAST-NUCES FYP report F26-030, Oct 10 2026).

**Status at plan time:** Phase 0 (wireless AP + inline Suricata) is reported complete in the source
document. This roadmap plans everything after that point.

## Why split into 8 documents

The spec (Section 6.6.7) itself names six runtime service directories plus a `common/` package and a
`training/` pipeline — these are already separable subsystems with their own test cycles, not an
artificial split. A single plan covering kernel netfilter config, three different ML algorithms, a
fault-tolerant supervisor, and a web dashboard would be thousands of lines and impossible to review
as one unit. Each phase below produces working, independently testable software; later phases depend
on earlier ones only through the fixed contracts in Phase 1.

## Phase order and dependencies

| Phase | Plan file | Produces | Depends on |
|---|---|---|---|
| 0 | *(done — not planned here)* | Wireless AP (hostapd/dnsmasq), inline Suricata on NFQUEUE, NAT | — |
| 1 | `2026-10-10-01-common-foundations.md` | `common/` package: DB schema + migrations, event-bus client, message schemas, config loader, logging | Phase 0 |
| 2 | `2026-10-10-02-flow-extraction-arp-anomaly.md` | `services/flowextract/`, `services/arpmon/`, Suricata eve.json bridge, Layer 2 (Isolation Forest + calibration + host-behaviour tracker) | Phase 1 |
| 3 | `2026-10-10-03-attack-classification.md` | `services/mlscorer/classifier` — Layer 3 (RF/XGBoost) | Phase 1, Phase 2 (consumes `FlowFeatures`) |
| 4 | `2026-10-10-04-decision-fusion-enforcement.md` | `services/decision/`, `services/enforcer/` — verdict fusion, host risk score, ipset blocking | Phase 1, Phase 2, Phase 3 (consumes Evidence from both) |
| 5 | `2026-10-10-05-watchdog-reliability.md` | `services/watchdog/`, `deploy/` systemd units — heartbeats, state machine, failure modes | Phase 1 (consumes ComponentHealth schema); integrates with all services from Phase 2-4 |
| 6 | `2026-10-10-06-management-dashboard.md` | `services/dashboard/`, event store writer, auth, config API, 6-screen web UI | Phase 1-5 (reads/writes everything) |
| 7 | `2026-10-10-07-offline-training-pipeline.md` | `training/`, `models/` — dataset builder, trainer, evaluator, model registry packages | Phase 1 (consumes `FlowFeatures` schema + `ModelPackage` format); feeds models into Phase 2 and 3 |

Phases 2 and 7 can run concurrently once Phase 1 lands (the flow extractor's feature schema is fixed
by Phase 1, so the training pipeline doesn't need Phase 2's running service — it needs the same
`compute_features()` function, imported directly). Phase 3 needs Phase 2's `FlowFeatures` dataclass
but not its runtime. Phase 5 (watchdog) can be built in parallel with 2-4 and wired in last, since it
only needs the heartbeat contract from Phase 1.

## Suggested sprint mapping (2-week sprints, matching the spec's stated methodology)

The spec's Section 6.2.4 states an iterative/incremental method with 2-week sprints but gives no
calendar dates — this mapping is a reasonable schedule, not a requirement from the document:

- **Sprint 1-2:** Phase 1 (common foundations) — must land first, everything else blocks on it.
- **Sprint 3-4:** Phase 2 (flow extraction, ARP monitor, Layer 2) + start Phase 7 (training pipeline,
  dataset builder) in parallel.
- **Sprint 5:** Phase 3 (Layer 3 classifier) using models produced by Phase 7.
- **Sprint 6:** Phase 4 (decision fusion + enforcement).
- **Sprint 7:** Phase 5 (watchdog) — can overlap with sprints 3-6 if a second contributor is free.
- **Sprint 8-9:** Phase 6 (dashboard) — needs every other service emitting real data to be useful end
  to end, but its API layer and UI can be scaffolded against fixtures earlier.
- **Sprint 10:** Integration hardening — fault-injection tests (FR-8 suite), one-week alert-only soak
  test (NFR-10), performance benchmarking (Table 5.7), cross-dataset evaluation writeup (Table 5.6).

## Cross-cutting items every phase must respect

These are fixed in Phase 1 and must not be redefined differently by any later phase:

- **SQL schema** — the 12 tables in `common/db/schema.sql` (Section 4.9 of the spec data dictionary).
- **Event-bus message envelope and stream names** — `common/schemas.py` and the 4 Redis Streams
  (`nidps:evidence`, `nidps:verdicts`, `nidps:heartbeats`, `nidps:config_changes`).
- **`Detector` interface** — `common/detector.py`; every new detector (ArpMonitor, AnomalyDetector,
  AttackClassifier) implements `analyse()` and `heartbeat()` and nothing else is required of it.
- **Config keys and safe ranges** — `common/config_schema.py`, backed by `CONFIG_SETTING` table.
- **Numeric defaults not fixed by the spec** (the spec gives these only as "e.g." examples or leaves
  them unstated — see each value's rationale in Phase 1's plan): calibration `N_min=2000`,
  `δ=0.15`, beaconing `m=5` connections / `CV threshold=0.15`, fusion `θ_block=0.90`,
  `θ_alert=0.70`, `θ_c=0.50`, host risk block threshold `Θ=6.0` (this one *is* implied by the
  spec's own dashboard mockup, which shows "Host risk — 6.4 / 6.0"), watchdog CPU watermarks
  `high=0.85 / low=0.60`. Every one of these is a `CONFIG_SETTING` row with a `min_value`/
  `max_value`, so it is admin-tunable at runtime (FR-10.3) without being a hardcoded magic number.

## Known spec gaps carried into the plans (do not treat these as the plan-writer's error)

1. No calendar schedule exists in the source document — see "Suggested sprint mapping" above.
2. No literal SQL DDL exists in the source — Phase 1 authors it from the Section 4.9 data dictionary.
3. No literal event-bus JSON example exists in the source — Phase 1 authors it from the Figure 6.4
   class diagram + Section 4.9 tables.
4. Several numeric thresholds are given only as "e.g." examples or left unstated — Phase 1 fixes
   concrete defaults (listed above) as tunable config, not spec requirements.
5. The spec explicitly flags JA3 instability against browser TLS extension randomization and
   recommends keeping TLS fingerprinting isolated in the flow extractor so a future JA4 migration
   doesn't touch other components — Phase 2's plan preserves that isolation (fingerprinting lives
   behind one function, `compute_tls_fingerprint()`), but implementing JA4 itself is out of scope for
   this plan set.
6. The spec names Table 5.6 (cross-dataset F1 matrix) and Table 5.7 (performance measures) as
   templates to be filled from experiments — no project-specific numbers exist yet. Phase 7's plan
   and the Sprint 10 integration hardening step are where those experiments actually get run.

## Execution

Start with Phase 1. Each phase's plan file is self-contained once its dependencies (per the table
above) exist — hand it to superpowers:subagent-driven-development or superpowers:executing-plans on
its own.
