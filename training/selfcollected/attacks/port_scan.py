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
