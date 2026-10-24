# Dataset Download Links

Reference list of download sources for the three public datasets used in `nidps_report`
(§5.2.1). `unb.ca`, the official host, is currently down ("worldwide security vulnerability"
notice) — these are the verified working alternatives. Scope per dataset reflects the decisions
in `docs/decisions-log.md` (2026-10-21 entry): only the raw PCAPs are needed, never the
pre-extracted CSVs, per §5.2.3 of the report (flows must be regenerated with the project's own
extractor to avoid train/serve skew).

---

## CIC-IDS-2017 — full dataset (all 5 days, ~52 GB)

**Raw PCAPs (use this one):**
- https://huggingface.co/datasets/bvsam/cic-ids-2017/tree/main/pcap

```bash
for day in Monday-WorkingHours Tuesday-WorkingHours Wednesday-workingHours \
           Thursday-WorkingHours Friday-WorkingHours; do
  curl -L -o "${day}.pcap" \
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/${day}.pcap"
done
```

CSV mirrors (reference/sanity-check only, not for flow regeneration):
- https://www.kaggle.com/datasets/dhoogla/cicids2017
- https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset
- https://www.kaggle.com/datasets/bertvankeulen/cicids-2017 (corrected-labels version)

Citation: Sharafaldin, Habibi Lashkari & Ghorbani, *"Toward Generating a New Intrusion Detection
Dataset and Intrusion Traffic Characterization,"* ICISSP 2018, DOI `10.5220/0006639801080116`.
Known CSV/label errors documented in: Engelen, Rimmer & Joosen, *"Troubleshooting an Intrusion
Detection Dataset: The CICIDS2017 Case Study,"* IEEE SPW 2021 — this is why raw PCAPs are
regenerated rather than trusting the published CSVs.

---

## CSE-CIC-IDS2018 — **1 day only** (Fri-02-03-2018, Bot, ~42 GB)

Per the decisions log, only the Botnet day is kept (Zeus/Ares C2 check-in traffic — the only
genuine beaconing exemplar across all three datasets). Official AWS Open Data mirror, no account
needed:

```bash
aws s3 cp --no-sign-request --region ca-central-1 \
  "s3://cse-cic-ids2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap.zip" \
  ./cse-cic-ids2018-bot-pcap.zip
```

Direct REST listing (no AWS CLI needed) if you want to browse other days before committing:
```
https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&prefix=Original%20Network%20Traffic%20and%20Log%20data/
```

Full-bucket registry page (for reference — do not pull the whole 477 GB):
- https://github.com/awslabs/open-data-registry/blob/main/datasets/cse-cic-ids2018.yaml

CSV-only Kaggle fallback (not used for this project's flow regeneration, listed for completeness):
- https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv

Citation: Canadian Institute for Cybersecurity, *CSE-CIC-IDS2018 Dataset*, University of New
Brunswick. Attack schedule verified from an archived snapshot of the official page (Wayback
Machine, Feb 2023 capture of `unb.ca/cic/datasets/ids-2018.html`) since the live site is down.

---

## CIC-IoT-2023 — full dataset (raw pcap + csv, ~13 GB uncompressed)

**Raw PCAP source (unverified — try first):**
- https://ieee-dataport.org/documents/ciciot2023-dataset (DOI `10.21227/v63c-9998`, free account
  required). Claims to serve both `pcap/` and `csv/` directories; not yet confirmed working.

CSV-only Kaggle mirrors (fallback only — does **not** satisfy §5.2.3's raw-PCAP requirement):
- https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset
- https://www.kaggle.com/datasets/dhoogla/ciciotdataset2023
- https://www.kaggle.com/datasets/himadri07/ciciot2023

Citation: Canadian Institute for Cybersecurity, *CIC IoT Dataset 2023*, University of New
Brunswick.

**Open item (from decisions-log.md):** if the IEEE DataPort PCAPs don't pan out, this dataset may
be stuck on CSV-only data until `unb.ca` returns — flagged as a blocker for the "same extractor
for every dataset" requirement, not yet resolved.

---

## Self-collected dataset

No external link — captured on the project's own deployment per §5.2.2 (benign household/lab
traffic + attack traffic from an isolated, team-owned test network). Not downloaded from anywhere.
