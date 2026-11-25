"""Loads a .env file at the repo root into the process environment, if one exists, before any
service reads its NIDPS_* configuration. Without this, every NIDPS_* value had to be exported in
the shell (or manually `source`d from a file) before starting each service -- easy to forget, and
tedious with five-plus services each needing the same handful of variables.

python-dotenv's load_dotenv() never overrides a variable already set in the real environment, so
precedence is: explicit `export FOO=bar` in your shell > .env file > the hardcoded default each
service falls back to. That means CI, systemd unit files (Environment=...), and one-off overrides
(`NIDPS_DASHBOARD_PORT=9000 python3 -m services.dashboard.main`) all still work exactly as before
-- .env only fills in what you haven't already set."""
from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"


def load_env() -> None:
    load_dotenv(ENV_FILE)
