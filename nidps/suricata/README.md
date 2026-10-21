# Suricata (lab capture config)

Passive/IDS mode only — no NFQUEUE/IPS wiring here (that's separate Phase-0 dataplane work).

Start manually for a capture session:

    sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l <session_dir>

Test the config without running it:

    suricata -T -c nidps/suricata/suricata.yaml -i <host-only-interface>

## Emerging Threats Open ruleset

The configuration references the ET Open ruleset at its standard `suricata-update` location: `/var/lib/suricata/rules/suricata.rules`. 
Install or update it with:

    suricata-update --suricata-conf nidps/suricata/suricata.yaml

If your ET rules location differs, update the rule-files entry in suricata.yaml accordingly.
