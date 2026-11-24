# Layer 2 training and evaluation

How the Isolation Forest ("what's normal") model is trained and checked. Run everything from the
repo root. Requires `pip install -r requirements.txt`.

## Data split (report §5.2.2, §5.5.1)

| Use | Data | Notes |
|---|---|---|
| **Train** | CIC-IDS-2017 Monday (all benign) + CIC-IoT-2023 `Benign_Final` (4 pcaps) | Benign flows only. 80% fits the model, the held-out 20% sets the threshold. |
| **Test** | Self-collected captures on our own network | Never used for training or for the threshold. |

The same extractor (`FlowAssembler` + `parse_packet`) builds the flows for every dataset, so training and
live flows match. Raw pcaps and extracted flows are not in git (`data/` is ignored); they are shared as a zip.

## 1. Extract flows from a pcap

```
python -m training.build_features <file.pcap> --out data/features/<name>
```

Writes `features.npz` (78 features per flow) and `flows.csv` (addresses and ports). It runs on one core and
takes roughly 5k packets/s. `--max-packets N` stops early.

## 2. Train and register

```
python -m training.train_iforest --features data/features/cicids2017-monday \
    data/features/ciciot2023/BenignTraffic data/features/ciciot2023/BenignTraffic1 \
    data/features/ciciot2023/BenignTraffic2 data/features/ciciot2023/BenignTraffic3 \
    --db data/nidps.sqlite3 --version public-v2 --activate
```

Seed is fixed (42), so the same flows give the same model. This writes `models/artifacts/iforest-<version>.joblib`,
registers it in `model_package` with the feature hash, and stores the starting threshold in `calibration_state`.
The device refuses to load a model whose feature hash or extractor version does not match.

## 3. Evaluate on the test captures

```
python -m training.evaluate_iforest --db data/nidps.sqlite3 \
    --benign data/features/selfcollected/* [--attack <attack feature dirs>] --json out.json
```

Reports the false-alarm rate at the global threshold and at the per-network calibrated threshold
(Algorithm 5.4). With `--attack` it also reports the detection rate. If `flows.csv` is missing it skips the
flagged-destination list.

## Latest result (`public-v2`, see `docs/results/eval_public-v2.json`)

- Trained on 1,751,265 benign flows. Global threshold 0.696.
- Self-collected benign test set, 22,021 flows: **1.68%** false alarms at the global threshold, **0.50%** at the
  calibrated threshold (0.716).
- The calibrated figure is partly circular: calibration targets the 99.5th percentile of the same traffic it is
  measured on. A fair figure would calibrate on part of the captures and test on the rest.
- No attack detection rate yet; it needs labelled attack captures from the test network.
