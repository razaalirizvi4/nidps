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
