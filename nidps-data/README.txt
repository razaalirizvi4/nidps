NIDPS Layer 2 data package
==========================

Unzip at the ROOT of the nidps repo (the folder that contains training/, services/, docs/).
The paths inside the zip mirror the repo, so everything lands where the scripts expect it.
Both folders are gitignored, so nothing here gets committed.

Contents
--------
data/features/cicids2017-monday/features.npz      CIC-IDS-2017 Monday, benign (training)
data/features/ciciot2023/BenignTraffic*/features.npz   CIC-IoT-2023 Benign_Final, 4 files (training)
data/features/selfcollected/session_*/features.npz     our own captures, 11 files (TEST ONLY)
models/artifacts/iforest-public-v2.joblib         trained Isolation Forest (convenience copy)

Each features.npz holds X (flows x 78 features) and feature_names. The flows.csv address files are
not included (they list addresses from personal captures).

Retrain (recommended; seed is fixed, so it reproduces the same model)
------------------------------------------------------------------
python -m training.train_iforest --features data/features/cicids2017-monday ^
  data/features/ciciot2023/BenignTraffic data/features/ciciot2023/BenignTraffic1 ^
  data/features/ciciot2023/BenignTraffic2 data/features/ciciot2023/BenignTraffic3 ^
  --db data/nidps.sqlite3 --version public-v2 --activate

Evaluate on our own captures (test set, never used for training)
----------------------------------------------------------------
python -m training.evaluate_iforest --db data/nidps.sqlite3 --benign data/features/selfcollected/*

Notes
-----
* The shipped .joblib is not registered in any database. Retraining registers it locally.
* Train/test split and details: docs/training-and-evaluation.md in the repo.
* Raw pcaps are not included (they are very large); only the extracted flows.
