# Suricata (lab capture config)

Passive/IDS mode only — no NFQUEUE/IPS wiring here (that's separate Phase-0 dataplane work).

Start manually for a capture session:

    sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l <session_dir>

Test the config without running it:

    suricata -T -c nidps/suricata/suricata.yaml -i <host-only-interface>

## Prerequisites

**Custom rules (4 active rules):** Included in `custom.rules` — work immediately with no setup required.

**Emerging Threats Open ruleset:** Optional; commented out by default because it requires a one-time setup step this environment cannot verify:

    sudo suricata-update --suricata-conf nidps/suricata/suricata.yaml

This downloads ET Open rules to `/var/lib/suricata/rules/suricata.rules`. Once installed, uncomment the ET entry in `nidps/suricata/suricata.yaml` line 84-85 to enable ET coverage.
