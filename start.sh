#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

set -a && source .env && set +a
source .venv/bin/activate
mkdir -p /tmp/nidps-logs

# Host IP, LAN subnet, gateway, DNS server, and the gateway's MAC all drift whenever you
# change networks (new router, different demo site, DHCP reassignment) -- detect them fresh
# from the capture interface at every startup instead of trusting whatever is in .env.
NIDPS_HOST_IP="$(ip -4 addr show dev "$NIDPS_CAPTURE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)"
NIDPS_HOME_NET="$(ip -4 route show dev "$NIDPS_CAPTURE_INTERFACE" scope link | grep -oP '^\d+(\.\d+){3}/\d+' | head -1)"
if [ -z "$NIDPS_HOST_IP" ] || [ -z "$NIDPS_HOME_NET" ]; then
  echo "Could not detect an IP/subnet on interface $NIDPS_CAPTURE_INTERFACE" >&2
  exit 1
fi

NIDPS_GATEWAY_IP="$(ip route show default dev "$NIDPS_CAPTURE_INTERFACE" | grep -oP '(?<=via\s)\d+(\.\d+){3}' | head -1)"
if [ -z "$NIDPS_GATEWAY_IP" ]; then
  echo "Could not detect a default gateway on interface $NIDPS_CAPTURE_INTERFACE" >&2
  exit 1
fi

# Populate the ARP cache for the gateway, then read its MAC back out of it.
ping -c1 -W1 "$NIDPS_GATEWAY_IP" >/dev/null 2>&1 || true
NIDPS_AP_MAC="$(ip neigh show "$NIDPS_GATEWAY_IP" dev "$NIDPS_CAPTURE_INTERFACE" | grep -oP '(?<=lladdr\s)[0-9a-f:]+' | head -1)"
if [ -z "$NIDPS_AP_MAC" ]; then
  echo "Could not resolve the gateway's MAC address via ARP ($NIDPS_GATEWAY_IP on $NIDPS_CAPTURE_INTERFACE)" >&2
  exit 1
fi

NIDPS_DNS_IP=""
if command -v resolvectl >/dev/null 2>&1; then
  NIDPS_DNS_IP="$(resolvectl dns "$NIDPS_CAPTURE_INTERFACE" 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}')"
fi
if [ -z "$NIDPS_DNS_IP" ]; then
  NIDPS_DNS_IP="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
fi
if [ -z "$NIDPS_DNS_IP" ]; then
  NIDPS_DNS_IP="$NIDPS_GATEWAY_IP"
fi

export NIDPS_HOST_IP NIDPS_GATEWAY_IP NIDPS_AP_MAC NIDPS_DNS_IP
echo "Detected host IP $NIDPS_HOST_IP on $NIDPS_CAPTURE_INTERFACE (subnet $NIDPS_HOME_NET)"
echo "Detected gateway $NIDPS_GATEWAY_IP (MAC $NIDPS_AP_MAC), DNS $NIDPS_DNS_IP"

echo "[1/10] Starting Redis..."
sudo systemctl start redis-server
echo "      Redis started."

echo "[2/10] Starting Suricata..."
sudo suricata -c nidps/suricata/suricata.yaml -i "$NIDPS_CAPTURE_INTERFACE" -l /tmp \
  --set "vars.address-groups.HOME_NET=[$NIDPS_HOME_NET]" \
  > /tmp/nidps-logs/suricata.log 2>&1 &
echo "      Suricata PID $!"

echo "[3/10] Starting flow extractor..."
sudo -E env \
  PATH="$PATH" \
  VIRTUAL_ENV="$VIRTUAL_ENV" \
  NIDPS_DB_PATH="$NIDPS_DB_PATH" \
  NIDPS_REDIS_URL="$NIDPS_REDIS_URL" \
  NIDPS_CAPTURE_INTERFACE="$NIDPS_CAPTURE_INTERFACE" \
  python3 -m services.flowextract.main \
  > /tmp/nidps-logs/flowextract.log 2>&1 &
echo "      flowextract PID $!"

echo "[4/10] Starting ARP monitor..."
sudo -E env \
  PATH="$PATH" \
  VIRTUAL_ENV="$VIRTUAL_ENV" \
  NIDPS_DB_PATH="$NIDPS_DB_PATH" \
  NIDPS_REDIS_URL="$NIDPS_REDIS_URL" \
  NIDPS_CAPTURE_INTERFACE="$NIDPS_CAPTURE_INTERFACE" \
  NIDPS_GATEWAY_IP="$NIDPS_GATEWAY_IP" \
  NIDPS_AP_MAC="$NIDPS_AP_MAC" \
  python3 -m services.arpmon.main \
  > /tmp/nidps-logs/arpmon.log 2>&1 &
echo "      arpmon PID $!"

echo "[5/10] Starting Suricata bridge..."
python3 -m services.sigbridge.main \
  > /tmp/nidps-logs/sigbridge.log 2>&1 &
echo "      sigbridge PID $!"

echo "[6/10] Starting ML scorer..."
python3 -m services.mlscorer.anomaly_service \
  > /tmp/nidps-logs/mlscorer.log 2>&1 &
echo "      mlscorer PID $!"

echo "[7/10] Starting decision engine..."
python3 -m services.decision.main \
  > /tmp/nidps-logs/decision.log 2>&1 &
echo "      decision PID $!"

echo "[8/10] Starting enforcer..."
sudo -E env \
  PATH="$PATH" \
  VIRTUAL_ENV="$VIRTUAL_ENV" \
  NIDPS_DB_PATH="$NIDPS_DB_PATH" \
  NIDPS_REDIS_URL="$NIDPS_REDIS_URL" \
  NIDPS_GATEWAY_IP="$NIDPS_GATEWAY_IP" \
  NIDPS_HOST_IP="$NIDPS_HOST_IP" \
  NIDPS_DNS_IP="$NIDPS_DNS_IP" \
  python3 -m services.enforcer.main \
  > /tmp/nidps-logs/enforcer.log 2>&1 &
echo "      enforcer PID $!"

echo "[9/10] Starting dashboard backend..."
python3 -m services.dashboard.main \
  > /tmp/nidps-logs/dashboard.log 2>&1 &
echo "      dashboard PID $!"

echo "[10/10] Starting dashboard frontend..."
(cd frontend && python3 -m http.server 5173) \
  > /tmp/nidps-logs/frontend.log 2>&1 &
echo "      frontend PID $!"

echo ""
echo "All services started. Logs: /tmp/nidps-logs/"
echo "Watch all logs:  tail -f /tmp/nidps-logs/*.log"
echo "Watch verdicts:  watch -n2 'sqlite3 $NIDPS_DB_PATH \"SELECT verdict_id, decision, layers, explanation FROM verdict ORDER BY verdict_id DESC LIMIT 10\"'"
echo "Dashboard:       http://localhost:5173  (API on :8443)"
echo "First time only, create an admin login before logging in:"
echo "  python3 -m services.dashboard.create_admin \"\$NIDPS_DB_PATH\" admin <a-real-password>"
