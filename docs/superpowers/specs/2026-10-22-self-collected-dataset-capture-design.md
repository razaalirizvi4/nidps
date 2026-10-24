# Self-Collected Dataset Capture Infrastructure — Design

**Status:** approved by user 2026-10-22, pending spec self-review and implementation plan.

## Context

The report (`nidps_report/chapters/ch5.tex`, §5.2.2 "Self-Collected Real-World Dataset")
requires a fourth, self-collected dataset captured on the project's own deployment, used only
for testing/evaluation (never training). It has two parts:

1. A **benign capture** — normal traffic, with any flow Suricata alerts on during the window
   excluded before the capture is labelled benign.
2. An **attack capture** — each in-scope attack executed from a dedicated attacker machine on an
   isolated, team-owned test network, with start time, end time, attacker address and target
   logged so every flow in that window can be labelled automatically from those logs.

This spec covers the infrastructure to actually produce that capture: bringing Suricata into the
repo, scripting the in-scope attacks, and orchestrating the capture + metadata logging. It does
**not** cover flow extraction/labelling into ML-ready feature records — that depends on the flow
extractor (Phase 2 of the implementation roadmap, `docs/superpowers/plans/2026-10-10-02-...`),
which does not exist in this repo yet.

Related: `docs/decisions-log.md` (dataset download-scope decisions), `docs/dataset-links.md`
(public dataset sources).

## Goals

- Bring the already-installed, global Suricata configuration into the repo at `nidps/suricata/`,
  matching the source layout in ch6 §6.6.7.
- Run Suricata in passive/IDS (alert-only) mode against the lab's VirtualBox host-only network,
  producing `eve.json` alerts — sufficient for benign-flow exclusion and signature evidence,
  without building the full inline NFQUEUE/iptables dataplane (that is separate Phase-0 work,
  already reported complete in the source document per the master roadmap).
- Script all 10 in-scope attacks with a single consistent runner, so every attack run produces
  one structured, timestamped log record regardless of which underlying tool executed it.
- Orchestrate capture sessions (benign and per-attack) that package the raw pcap, Suricata
  alerts, and attack metadata together per session.

## Non-goals (explicit scope boundary)

- **No flow extraction or feature labelling.** Output stops at raw pcap + `eve.json` +
  `attacks.jsonl`. Turning these into labelled 78-feature flow records requires the flow
  extractor, which is out of scope here.
- **No inline/NFQUEUE Suricata deployment, no iptables/ipset enforcement.** Passive capture only.
- **No ARP-consistency monitor service.** ARP spoofing is still scripted and captured as an
  attack, but there is no live ARP monitor detecting it in this pass — that's the `arpmon`
  service from Phase 2.
- **No automated test suite for the attacks themselves** beyond a `--dry-run` validation mode —
  this is inherently a live-network exercise run by hand against real lab VMs.

## Lab Topology

- **Host** (this machine, this repo): runs Suricata (passive) + `tcpdump`/`dumpcap`, and is where
  the attack-runner CLI and capture orchestration are invoked from (SSH'd into the Kali VM, or run
  locally on each VM as appropriate per attack — see per-attack notes).
- **VirtualBox**, all VMs on a shared **Host-only Network** adapter, with **Promiscuous Mode set
  to "Allow All"** in each VM's network adapter advanced settings — this is what lets the host see
  inter-VM traffic on the host-only interface (e.g. `vboxnet0`) as a passive observer, without
  acting as a router/bridge between the VMs.
- **Kali VM** — attacker.
- **Ubuntu VM ("victim-A")** — primary victim; initial-compromise target for most attacks.
- **Ubuntu (or similar) VM ("victim-B")** — second internal host, used only for the lateral
  movement / infiltration attack, so that scan traffic genuinely originates from an internal host
  (victim-A) rather than the external attacker (Kali) — matching the taxonomy's definition of
  infiltration as "internal scanning after compromise" (Table 5.2).

## Component 1: Suricata Bring-up (`nidps/suricata/`)

- Copy the existing global Suricata install's config into the repo:
  - `nidps/suricata/suricata.yaml` — adapted from the global config. Key changes from the global
    install: `af-packet` interface set to the VirtualBox host-only interface (e.g. `vboxnet0`
    or whatever the host's adapter is named); run mode is IDS/alert-only (no NFQUEUE/IPS
    settings wired up); `eve.json` output path set to a per-run log directory used by the
    capture pipeline (Component 3).
  - `nidps/suricata/custom.rules` — the 5 Suricata-expressible custom rules from Table 5.4:
    SSH brute force (threshold on new connections to :22), port scan (threshold on SYNs to many
    distinct ports), DNS spoofing (response from non-AP source), known-bad JA3 (blocklist
    match), SYN flood (rate threshold). Emerging Threats Open ruleset stays enabled alongside
    these for general coverage.
  - A placeholder `nidps/suricata/rule-update.sh` noted but **not wired to a scheduler** in this
    pass (§6.6.1's daily rule-update job is out of scope here).
- Suricata is started manually for a capture session (see Component 3), not as a persistent
  systemd service yet — that's `deploy/` work, out of scope here.

## Component 2: Attack Toolkit (`training/selfcollected/attacks/`)

### Shared runner (`attacks/common/runner.py`)

Responsibilities, common to every attack:
- Parses shared CLI args: `--attacker-ip`, `--victim-ip`, `--out-dir`, plus attack-specific
  kwargs passed through to the attack module.
- Preflight: checks required external tools exist (`shutil.which`) before starting; fails fast
  with a clear message naming the missing tool, rather than a buried subprocess error mid-run.
- Wraps the attack's `run(config)` call: records `start_time` (UTC, ISO 8601) immediately before
  invocation, `end_time` immediately after (success or failure), and always writes one JSON line
  to `attacks.jsonl` in `--out-dir`:
  ```json
  {
    "attack": "ssh_bruteforce",
    "tool": "hydra",
    "attacker_ip": "192.168.56.11",
    "victim_ip": "192.168.56.12",
    "start_time": "2026-10-22T10:32:01Z",
    "end_time": "2026-10-22T10:34:18Z",
    "status": "completed",
    "params": {"wordlist": "...", "port": 22},
    "notes": ""
  }
  ```
  `status` is one of `completed`, `failed` (with a `stderr_tail` field added), or `interrupted`
  (set by the signal handler below).
- Installs SIGINT/SIGTERM handlers around the attack's execution so that: (a) any spawned
  subprocess (hydra, hping3, a beacon loop, etc.) is terminated rather than orphaned, and (b) a
  clean `end_time` + `status: "interrupted"` record is still written even on Ctrl-C.
- `--dry-run` flag: validates all args and tool availability, prints the exact command(s)/plan
  that would run, and exits without touching the network.
- Prints a one-line safety banner on every real (non-dry-run) invocation reminding that this
  must only be run against the isolated lab network (ties back to risk R10 in the report).

### Per-attack modules

| Module | Tool / approach | Notes |
|---|---|---|
| `ssh_bruteforce.py` | hydra against victim:22 | takes `--wordlist`; attacker→victim-A |
| `port_scan.py` | nmap | configurable scan type/port range; attacker→victim-A |
| `arp_spoof.py` | arpspoof | poisons victim-A's ARP cache toward attacker; prerequisite for `dns_spoof` |
| `dns_spoof.py` | dnsspoof | **depends on** `arp_spoof` already running/having run to put attacker on-path; module documents this dependency and does not silently chain to it |
| `syn_flood.py` | hping3 | SYN flood, attacker→victim-A |
| `ja3_c2.py` | custom (crafted TLS ClientHello) | connects with a cipher/extension list chosen to produce a JA3 hash matching a known-malicious entry on the custom blocklist rule in `custom.rules` |
| `c2_beacon.py` | custom Python | victim-A → attacker-hosted listener, periodic low-jitter connections; `--interval`, `--jitter`, `--count` |
| `exfiltration.py` | custom Python | victim-A → attacker, large/unusual outbound transfer (generated blob, configurable size) |
| `ddos.py` | hping3 flood | **single-source** volumetric flood — `attacks.jsonl` record notes this explicitly (`"notes": "single-attacker volumetric flood, not distributed"`) so downstream labelling doesn't overclaim |
| `lateral_movement.py` | nmap | run **from victim-A**, targeting victim-B and the subnet — source address is internal (victim-A), matching the taxonomy's "internal scanning after compromise" definition |

## Component 3: Capture Pipeline (`training/selfcollected/capture/capture_session.py`)

Orchestrates one session, benign or attack:

- Starts (if not already running) Suricata against the host-only interface, and a `tcpdump`/
  `dumpcap` capture writing `session.pcap` into a new `captures/<timestamp>-<label>/` directory.
- **Benign session:** captures ambient VM traffic for a configurable duration with no attack
  triggered. At the end, reads `eve.json` for the session window and writes a
  `benign_session_manifest.json` listing any alerted time ranges, so the calibration/benign
  baseline step downstream (§5.5.2) can exclude them later — this pipeline only flags them, it
  does not itself do the exclusion (that's a training-pipeline concern, Phase 7).
- **Attack session:** starts capture, invokes `run_attack.py <name> ...` (Component 2) for the
  chosen attack, stops capture once the attack reports completion plus a configurable settle
  buffer (default a few seconds, to catch trailing packets/replies).
- Every session directory ends up with: `session.pcap`, `eve.json` (copied/trimmed to the
  session window), `attacks.jsonl` (for attack sessions) or `benign_session_manifest.json` (for
  benign sessions).

## Testing

- Each attack module: `--dry-run` as described above — the only automated check, since this is
  fundamentally a live-network exercise.
- Manual checklist (run once per attack against the lab VMs before considering this "working"):
  1. Run the attack for real.
  2. Confirm `attacks.jsonl` has a sane `start_time`/`end_time` and `status: "completed"`.
  3. Confirm Suricata fired an alert where expected: SSH brute force, port scan, DNS spoofing,
     known-bad JA3, SYN flood should all produce an `eve.json` alert. ARP spoofing, C2 beaconing,
     exfiltration, DDoS (hping3 flood may or may not trip a generic ET rule — not guaranteed),
     and lateral movement should **not** be expected to trigger a Suricata alert — they're
     Layer 2/3 targets, not Layer 1, and this absence is itself useful information for later
     evaluation (shows which layer is actually responsible for catching each class).

## Known Limitations / Open Items

- `dns_spoof.py` depends on `arp_spoof.py` having already put the attacker on-path; the two are
  not auto-chained, so running `dns_spoof` standalone against a victim that isn't already
  ARP-poisoned will not produce a meaningful spoof. Documented in the module, not solved by the
  runner.
- `ddos.py` is a single-source flood, not a distributed one — labelled as such in its log record.
- No labelled, ML-ready flow records come out of this component set. That is explicitly deferred
  to when the flow extractor (Phase 2) exists.
- No ARP-consistency monitor exists yet to actually detect the ARP spoofing attack live; it is
  still captured and logged for later offline evaluation once that detector exists.
- Suricata's rule auto-update job (§6.6.1) is not wired to a scheduler in this pass.

## Traceability

| Spec section | Addressed by |
|---|---|
| §5.2.2 Self-Collected Real-World Dataset | Components 2 + 3 |
| §5.4.1/5.4.2 Suricata config + custom rules (Table 5.4) | Component 1 |
| §5.4.3 ARP spoofing (captured, not detected live) | Component 2 (`arp_spoof.py`), ARP monitor deferred |
| Table 5.2 unified attack taxonomy | Component 2 module list |
| Risk R10 (attacks confined to isolated owned lab network) | Runner's safety banner + required `--attacker-ip`/`--victim-ip` args |
