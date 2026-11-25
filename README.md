# NIDPS — Developer Setup

This is a from-scratch network intrusion detection/prevention system. It is **not** a
single program — it's a handful of small services that each do one job (watch for
known attack signatures, watch for ARP spoofing, extract traffic flows, score flows
for anomalies) and talk to each other over Redis. There is currently **no one-command
launcher and no setup script** — this document is the manual steps until one exists.

If you just want to run the automated tests, skip to [Running the tests](#running-the-tests) —
that part needs none of the setup below.

## 1. What you need installed

- **Python 3.11+**
- **Redis** (`redis-server`) — every service talks to every other service through it.
- **Suricata** — the signature-matching layer. Not a Python dependency; install it
  separately (e.g. `sudo apt install suricata` on Debian/Ubuntu).
- Root (or `CAP_NET_RAW`) on whatever machine runs packet capture — the flow extractor
  and the ARP monitor both call `scapy.sniff()`, which needs raw-socket access.

```bash
git clone <this repo>
cd nidps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Find your real network interface

**Nothing in this project auto-detects which network interface to listen on.** Both
Suricata and the Python capture services default to placeholder values that are very
unlikely to be your real interface. Find yours first:

```bash
ip link        # or: ip a
```

Look for the interface that's actually up and carrying traffic (e.g. `eth0`, `wlan0`,
`enp3s0`, `wlp2s0` — it varies by machine). You'll need this name in step 4 and when
starting Suricata.

## 3. Set up the database

Connecting to the database auto-creates the schema (tables) the first time — but it
does **not** fill in default settings (thresholds, timeouts, etc.). Nothing calls that
seeding step automatically yet, so do it once by hand before starting any service:

```bash
python3 -c "
from common.db.migrate import connect
from common.config_loader import seed_defaults
conn = connect('./nidps.sqlite3')   # creates the file + schema if missing
seed_defaults(conn)                  # fills in every setting's default value
print('database ready at ./nidps.sqlite3')
"
```

Use a path you can actually write to. The services default to
`/var/lib/nidps/nidps.sqlite3`, which requires root and won't exist on a fresh
checkout — for local dev, point everything at a local file instead (see step 4).

Re-running this command is safe — it won't wipe or duplicate anything that's already there.

## 4. Environment variables

Every service reads its configuration from environment variables, all prefixed `NIDPS_`. None of
these have a setup wizard, but they don't need exporting by hand either: every service calls
`common.env.load_env()` as the first thing it does, which loads a `.env` file at the repo root
into the process automatically (via `python-dotenv`). A value you've already exported in your
shell always wins over `.env` — it only fills in what you haven't set some other way.

```bash
cp .env.example .env
```

Then edit `.env` — see the comments in `.env.example` for what each key does. `.env` is gitignored
(it's local machine config, not something to share/commit); `.env.example` is the tracked template.

| Variable | Used by | Default if unset | Notes |
|---|---|---|---|
| `NIDPS_DB_PATH` | all services | `/var/lib/nidps/nidps.sqlite3` | Point this at the file you created in step 3. |
| `NIDPS_REDIS_URL` | all services | `redis://localhost:6379/0` | Fine as-is if Redis is running locally on the default port. |
| `NIDPS_CAPTURE_INTERFACE` | flow extractor, ARP monitor | `wlan0` | **Set this to the interface you found in step 2** — the default is almost never correct. |
| `NIDPS_GATEWAY_IP` | ARP monitor | *(required, no default — will crash without it)* | Your network's gateway IP address. |
| `NIDPS_AP_MAC` | ARP monitor | *(required, no default — will crash without it)* | The MAC address of this machine's access-point interface. |
| `NIDPS_DHCP_LEASE_PATH` | ARP monitor | `/var/lib/misc/dnsmasq.leases` | Only matters if you're actually running dnsmasq; otherwise the monitor just won't know about any devices. |
| `NIDPS_EVE_JSON_PATH` | Suricata bridge | `/var/log/suricata/eve.json` | Must match wherever you tell Suricata to write its log in step 5. |
| `NIDPS_DASHBOARD_HOST` / `NIDPS_DASHBOARD_PORT` | dashboard | `0.0.0.0` / `8443` | See step 7. |
| `NIDPS_DASHBOARD_CORS_ORIGINS` | dashboard | *(unset — no CORS headers sent)* | Comma-separated frontend origin(s), needed only if the frontend runs on a different port (step 7). |

A one-off override still works exactly like before, e.g. for a quick different port without
touching `.env`:

```bash
NIDPS_DASHBOARD_PORT=9000 python3 -m services.dashboard.main
```

## 5. Start the infrastructure

```bash
redis-server &                 # if it isn't already running as a system service
```

Start Suricata manually, pointing it at your real interface and the log path from
`NIDPS_EVE_JSON_PATH`:

```bash
sudo suricata -c nidps/suricata/suricata.yaml -i <your-interface> -l /tmp
```

(See `nidps/suricata/README.md` for the optional step to pull in the full Emerging
Threats ruleset — the custom rules work out of the box without it.)

## 6. Start each detection service

There is no combined launcher — open a separate terminal (with the same environment
variables exported) for each of these:

```bash
python3 -m services.flowextract.main     # needs root/CAP_NET_RAW (packet capture)
python3 -m services.arpmon.main          # needs root/CAP_NET_RAW (packet capture)
python3 -m services.sigbridge.main       # reads Suricata's eve.json
python3 -m services.mlscorer.anomaly_service
```

**Heads up:** `anomaly_service` will start and run fine, but its anomaly-scoring half
stays switched off until a real trained model exists in the database — nothing
trains or loads one automatically yet. It'll log a warning and keep running with
just the host-behaviour checks (data-volume and beaconing detection) active.

## 7. Start the management dashboard

A web dashboard now exists (`services/dashboard/`): session-authenticated REST API plus a
`/ws/live` WebSocket, serving the Login, Overview, Intrusion Alerts, Blocked Hosts & Allowlist,
Configuration, and System Health screens. Create the first admin login once, then start it like
any other service (same environment variables as above, plus `NIDPS_DASHBOARD_PORT` if you don't
want the 8443 default):

```bash
python3 -m services.dashboard.create_admin ./nidps.sqlite3 admin <a-real-password>
python3 -m services.dashboard.main
```

Two gaps worth knowing about, both pre-existing in the rest of the system rather than bugs in the
dashboard: **Blocked Hosts** will show nothing until an enforcement service starts writing
`block_entry` rows (none exists yet — nothing currently turns a BLOCK verdict into an actual
ipset block), and **System Health**'s component table will be empty until a watchdog service
starts writing `component_event` rows (also not yet built). The dashboard's Unblock / Reload
Rules / Recalibrate buttons publish to a `nidps:admin_commands` stream that nothing consumes yet
for the same reason — see `services/dashboard/admin_commands.py`.

## Running the tests

This needs none of the above — no Redis, no Suricata, no root, no real network
interface. Everything is faked/in-memory.

```bash
source .venv/bin/activate
pytest tests -q
```

## What's intentionally not here yet

This README only covers running what's already built. Still missing from the full system: a
trained anomaly model (step 6 above), the enforcement layer that turns a BLOCK verdict into an
actual ipset block (and writes `block_entry`), a watchdog service, and a setup/launcher script to
replace steps 3–7 above with one command. If you're picking up one of those, check
`docs/superpowers/plans/` for the relevant design doc first.
