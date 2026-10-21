from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from pathlib import Path


@dataclasses.dataclass
class AttackRecord:
    attack: str
    tool: str
    attacker_ip: str
    victim_ip: str
    start_time: str
    end_time: str
    status: str  # "completed" | "failed" | "interrupted" | "dry_run"
    params: dict
    notes: str = ""
    stderr_tail: str = ""

    def to_json_line(self) -> str:
        return json.dumps(dataclasses.asdict(self))


def check_tools(tool_names: list[str]) -> None:
    missing = [t for t in tool_names if shutil.which(t) is None]
    if missing:
        raise FileNotFoundError(
            f"Required tool(s) not found on PATH: {', '.join(missing)}. "
            f"Install them before running this attack."
        )


def append_record(out_dir: Path, record: AttackRecord) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "attacks.jsonl"
    with path.open("a") as f:
        f.write(record.to_json_line() + "\n")


def run_subprocess(cmd: list[str], timeout: float | None = None) -> None:
    """Runs cmd to completion; raises CalledProcessError (with .stderr set) on nonzero exit."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, output=result.stdout, stderr=result.stderr
        )
