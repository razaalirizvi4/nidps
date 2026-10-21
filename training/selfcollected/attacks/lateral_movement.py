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
