#!/usr/bin/env bash
# Placeholder for the daily ET Open ruleset update job (report §6.6.1).
# NOT wired to a scheduler in this plan — run manually if/when needed:
#   suricata-update --suricata-conf nidps/suricata/suricata.yaml
set -euo pipefail
echo "rule-update.sh is a placeholder; not scheduled. Run suricata-update manually." >&2
exit 1
