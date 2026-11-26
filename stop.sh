#!/usr/bin/env bash
echo "Stopping NIDPS services..."

# Python services
pkill -f "services\.flowextract\.main" && echo "  stopped flowextract" || echo "  flowextract not running"
pkill -f "services\.arpmon\.main"      && echo "  stopped arpmon"      || echo "  arpmon not running"
pkill -f "services\.sigbridge\.main"   && echo "  stopped sigbridge"   || echo "  sigbridge not running"
pkill -f "services\.mlscorer\.anomaly" && echo "  stopped mlscorer"    || echo "  mlscorer not running"
pkill -f "services\.decision\.main"    && echo "  stopped decision"    || echo "  decision not running"
pkill -f "services\.enforcer\.main"    && echo "  stopped enforcer"    || echo "  enforcer not running"
pkill -f "services\.dashboard\.main"   && echo "  stopped dashboard"   || echo "  dashboard not running"
pkill -f "http.server 5173"           && echo "  stopped frontend"    || echo "  frontend not running"

# Suricata (only the ones we launched, not the system service)
sudo pkill -f "suricata -c nidps/suricata/suricata.yaml" && sleep 1 && sudo pkill -9 -f "suricata -c nidps/suricata/suricata.yaml" 2>/dev/null; echo "  stopped suricata"

echo "Done."
echo ""
echo "Remaining NIDPS processes (should be empty):"
ps aux | grep -E "services\.(flowextract|arpmon|sigbridge|mlscorer|decision|enforcer|dashboard)|http.server 5173|suricata -c nidps" | grep -v grep || echo "  none"
