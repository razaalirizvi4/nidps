# Decisions Log

Running log of project decisions made outside the FYP report/plans themselves — things agreed
in working sessions that affect how the spec in `nidps_report/` gets executed. Newest entries on
top. Each entry: decision, rationale, verification, and what it changes about the plan.

---

## 2026-10-21 — Dataset download scope (training data acquisition)

**Context:** `unb.ca` (the official host for all three public datasets) is down ("worldwide
security vulnerability," confirmed via a live fetch of the site, which now just serves an outage
notice). Mirrors exist, but a full raw-PCAP download of all three datasets badly exceeds the
training workstation's stated disk budget (§4.7.1 of the report: ≥16 GB RAM, 32 GB recommended,
**≥200 GB free disk**). CSE-CIC-IDS2018 alone is 477 GB raw. Decided to trim it to only the days
that add real value, using the other two datasets already in the pipeline to cover redundant
classes.

**Decision: keep only 1 of CSE-CIC-IDS2018's 10 days — Fri-02-03-2018 (Bot).**

| Day(s) | Attack(s) | Decision | Why |
|---|---|---|---|
| Thu-22-02, Fri-23-02-2018 | Brute Force-Web, Brute Force-XSS, SQL Injection | **Cut** | Not a class in the project's unified taxonomy (Table 5.2) at all |
| Wed-14-02-2018 | FTP-BruteForce, SSH-Bruteforce | **Cut** | Brute force already explicit in both CIC-IDS-2017 and CIC-IoT-2023 (Table 5.1) |
| Thu-15-02, Fri-16-02, Tue-20-02, Wed-21-02-2018 (4 days) | DoS-GoldenEye/Slowloris/SlowHTTPTest/Hulk, DDoS-LOIC-HTTP/UDP/HOIC | **Cut** | DoS/DDoS already explicit in both other datasets; this was 4 of CSE-CIC-IDS2018's 10 days for one class |
| Wed-28-02, Thu-01-03-2018 (2 days) | Infiltration | **Cut** | CIC-IDS-2017's own Infiltration scenario (Thu 6 Jul 2017, ~14:19–15:00: Dropbox/USB-delivered Metasploit exploit → attacker runs Nmap/portscan across the internal victim network from the compromised host) is **structurally identical** — same "post-compromise internal lateral recon" shape the taxonomy defines, same CIC research group. Verified by pulling the actual attack description, not assumed. **Accepted trade-off:** CIC-IDS-2017's infiltration window is only ~40 min vs. CSE-CIC-IDS2018's ~75+155 min — roughly 5x less volume of an already-rare class (<1% of CSE-CIC-IDS2018 traffic). Accepted anyway. |
| Fri-02-03-2018 (1 day) | Bot (Zeus + Ares) | **Kept** | NOT redundant with CIC-IoT-2023's "Mirai" despite both nominally mapping to Botnet/C2 in Table 5.2. Verified the actual CICIoT2023 paper: its "Mirai" category is three DDoS flood sub-attacks (Mirai-greeth_flood, Mirai-greip_flood, Mirai-udpplain) — GRE/UDP packet floods, not bot-to-C2 check-in traffic. It exercises the DoS/DDoS detector, not C2 beaconing. CSE-CIC-IDS2018's Zeus/Ares day is the **only** dataset in the whole pipeline with genuine periodic C2 check-in traffic to validate the JA3/CV-beaconing detector (§5.5.4) against. |

**Open item flagged, not yet acted on:** this also means Table 5.2 of the report (which lists
"Mirai variants" as an example under Botnet/C2 without qualification) is slightly imprecise for
CICIoT2023 specifically — worth a one-line clarification in the report if there's time, but not
blocking.

### Resulting dataset footprint (raw PCAP, training workstation)

| Dataset | Scope | Size | Verification |
|---|---|---|---|
| CIC-IDS-2017 | All 5 days (full) | ~52 GB | Hugging Face mirror (`bvsam/cic-ids-2017`), per-file sizes reported there |
| CSE-CIC-IDS2018 | 1 day only (Fri-02-03-2018, Bot) | **41.93 GB** | Queried directly via the public S3 bucket's REST API (`cse-cic-ids2018.s3.ca-central-1.amazonaws.com`) — exact, not estimated |
| CIC-IoT-2023 | Full (raw pcap + csv) | ~13 GB uncompressed | Reported dataset size from Kaggle listings; **not independently verified against a bucket/API** the way the other two were — treat as approximate until downloaded |
| Self-collected | N/A | 0 (not downloaded — captured locally per §5.2.2) | — |

**Total: ≈ 107 GB**, against the ≥200 GB budget — leaves ~90+ GB of headroom for the processed
flow-feature tables, model artifacts, and working space during flow regeneration.

**Written into the report:** this day-selection rationale is now documented in
`nidps_report/chapters/ch5.tex`, §5.2.4 (Pre-processing), as a new bullet ahead of "Invalid values."

**Still open:** CIC-IoT-2023's raw PCAP source itself is unconfirmed — `unb.ca` is down, Kaggle
mirrors found so far are CSV-only (pre-extracted features, not raw packets), and IEEE DataPort
(DOI `10.21227/v63c-9998`) is the best lead but untested. Needed because §5.2.3 requires every
dataset to go through the project's own flow extractor from raw packets, not pre-extracted CSVs.
