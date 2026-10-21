# Suricata (lab capture config)

Passive/IDS mode only — no NFQUEUE/IPS wiring here (that's separate Phase-0 dataplane work).

Start manually for a capture session:

    sudo suricata -c nidps/suricata/suricata.yaml -i <host-only-interface> -l <session_dir>

Test the config without running it:

    suricata -T -c nidps/suricata/suricata.yaml -i <host-only-interface>
