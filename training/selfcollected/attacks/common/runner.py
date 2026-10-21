from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from pathlib import Path
import signal
import sys
from datetime import datetime, timezone
from typing import Callable


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


class AttackInterrupted(Exception):
    """Raised internally when SIGINT/SIGTERM is received during an attack body."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_attack(
    attack_name: str,
    tool: str,
    attacker_ip: str,
    victim_ip: str,
    out_dir: Path,
    params: dict,
    body: Callable[[], None],
    dry_run: bool = False,
) -> AttackRecord:
    print(
        f"[SAFETY] Running '{attack_name}' against {victim_ip} from {attacker_ip}. "
        f"This must only run on an isolated lab network you own.",
        file=sys.stderr,
    )

    if dry_run:
        print(f"[DRY RUN] Would run '{attack_name}' (tool={tool}) "
              f"attacker={attacker_ip} victim={victim_ip} params={params}")
        timestamp = _utc_now_iso()
        record = AttackRecord(
            attack=attack_name, tool=tool, attacker_ip=attacker_ip,
            victim_ip=victim_ip, start_time=timestamp, end_time=timestamp,
            status="dry_run", params=params,
        )
        append_record(out_dir, record)
        return record

    def _handler(signum, frame):
        raise AttackInterrupted()

    old_int = signal.signal(signal.SIGINT, _handler)
    old_term = signal.signal(signal.SIGTERM, _handler)

    start = _utc_now_iso()
    status = "completed"
    stderr_tail = ""
    try:
        body()
    except AttackInterrupted:
        status = "interrupted"
    except subprocess.CalledProcessError as exc:
        status = "failed"
        stderr_tail = (exc.stderr or "")[-2000:]
    except Exception as exc:  # must always record, even on an unexpected error
        status = "failed"
        stderr_tail = str(exc)[-2000:]
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)

    end = _utc_now_iso()
    record = AttackRecord(
        attack=attack_name, tool=tool, attacker_ip=attacker_ip,
        victim_ip=victim_ip, start_time=start, end_time=end,
        status=status, params=params, stderr_tail=stderr_tail,
    )
    append_record(out_dir, record)
    return record


def run_timed_subprocess(cmd: list[str], duration: float) -> None:
    """Runs cmd in the background for `duration` seconds, then terminates it cleanly.

    Raises CalledProcessError if cmd exits on its own with a nonzero code before
    `duration` elapses.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return
    if proc.returncode != 0:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise subprocess.CalledProcessError(proc.returncode, cmd, stderr=stderr)
