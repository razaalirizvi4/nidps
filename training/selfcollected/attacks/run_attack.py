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
