# Project Phalanx

**Home Network Guardian** — A plug-and-play Raspberry Pi 4 appliance that blocks ads, monitors network traffic, and alerts non-technical users to suspicious activity.

## Project structure

```
phalanx/
├── run.sh              ← Start here. Runs both layers in order.
├── config.env          ← Shared network config (IP, gateway, subnet)
│
├── base/               ← LAYER 1: OS hardening (by teammate)
│   └── install.sh      ← Creates admin user, firewall, SSH lockdown, static IP
│
└── app/                ← LAYER 2: Phalanx application
    ├── main.py         ← Entry point and orchestrator
    ├── requirements.txt
    ├── config/         ← Tunables (DNS, blocklist, alerting, resource limits)
    ├── core/
    │   ├── database.py     ← SQLite schema + versioned migrations
    │   ├── dns_proxy.py    ← Async UDP DNS proxy with LRU cache
    │   ├── blocklist.py    ← Blocklist download/parse, subscription gating
    │   ├── monitor.py      ← Per-device traffic tracking + anomaly detection
    │   └── subscription.py ← Auth + subscription lifecycle
    ├── api/
    │   └── server.py       ← REST API + embedded fallback dashboard
    └── scripts/
        ├── install.sh      ← App installer (runs after base)
        └── phalanx.service ← systemd unit
```

## Setup

### Prerequisites

- Raspberry Pi 4 (4GB RAM) with Raspberry Pi OS
- Internet connection
- An SSH key pair on your personal computer

### Installation

```bash
# 1. Copy project to the Pi and SSH in
scp -r phalanx/ pi@<pi-ip>:~/
ssh pi@<pi-ip>

# 2. Run the full setup
cd ~/phalanx
chmod +x run.sh
sudo bash run.sh
```

The script walks you through two layers:

**Layer 1 — Base system** (interactive prompts):
- Creates a new admin user (replaces default `pi` user)
- Sets a strong password policy (12+ chars, mixed case, numbers, special chars)
- Configures a static IP
- Sets up UFW firewall (SSH, DNS, HTTP, HTTPS on local subnet only)
- Locks SSH to key-only authentication

**Layer 2 — Phalanx application**:
- Installs Python dependencies (`aiohttp`, `psutil`)
- Deploys the DNS proxy, blocklist engine, and dashboard
- Configures systemd for auto-start on boot
- Downloads the initial blocklist (~200k domains)

### After installation

```bash
# Dashboard
http://<static-ip>

# Logs
sudo journalctl -u phalanx -f

# SSH (from your personal computer)
ssh <username>@<static-ip>
```

**Point your router's DHCP DNS setting to the Pi's static IP** so all devices on the network route DNS through Phalanx.

## What it does

- **Ad & tracker blocking** — DNS proxy blocks queries to known ad/tracker domains. Ships with the free StevenBlack list (~200k domains). Subscription tier adds auto-updating curated lists.
- **Traffic monitoring** — Tracks per-device DNS activity, builds behavioral baselines over 72 hours, flags anomalies (query spikes, contact with unknown servers).
- **Smart alerting** — Groups and suppresses noisy alerts. A house with 20 IoT devices gets one rolled-up line item, not 20.
- **Subscription lifecycle** — Active → Grace (7 days) → Lapsed. When lapsed, the device keeps its last cached blocklist frozen. Never bricks.
- **Dashboard** — Shows devices online, domains blocked, DNS stats, device health, and alerts.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Sign in |
| POST | `/api/auth/logout` | Sign out |
| GET | `/api/auth/status` | Auth + subscription status |
| GET | `/api/dashboard` | Full dashboard summary |
| GET | `/api/devices` | All seen devices |
| POST | `/api/devices/rename` | Rename a device |
| GET | `/api/alerts` | Recent alerts |
| GET | `/api/alerts/grouped` | Alerts collapsed by group |
| GET | `/api/blocklist` | Blocklist stats |
| POST | `/api/blocklist/whitelist` | Whitelist a domain |
| DELETE | `/api/blocklist/whitelist` | Remove from whitelist |
| POST | `/api/blocklist/blacklist` | Blacklist a domain |
| GET | `/api/diagnostics` | System resources + DNS stats |

## What's done

- [x] Base OS hardening (admin user, firewall, SSH, static IP, password policy)
- [x] DNS proxy engine (async UDP, LRU cache, parent-domain matching)
- [x] Blocklist manager (hosts + domain-list parsing, subscription gating, freeze-on-lapse)
- [x] Traffic monitor (batched stats, behavioral baselines, anomaly detection, alert suppression)
- [x] Subscription manager (auth, ACTIVE → GRACE → LAPSED lifecycle)
- [x] Centralized SQLite schema with versioned migrations
- [x] REST API with all endpoints
- [x] Embedded fallback HTML dashboard
- [x] systemd service with resource limits
- [x] Integrated two-layer install script

## What's remaining

- [ ] Build the React GUI and connect to the live API
- [ ] Stand up the subscription cloud API backend
- [ ] Auto-detect device names/types (mDNS, DHCP leases, MAC vendor lookup)
- [ ] Unit tests (DNS proxy, blocklist parser, anomaly detection, subscription state)
- [ ] Persist whitelist/blacklist overrides to DB (currently in-memory only)
- [ ] Sync blocklist source metadata to DB for "why was this blocked?" lookups
- [ ] Device blocking from dashboard (drop DNS queries for blocked devices)
- [ ] HTTPS for the dashboard (self-signed cert on first boot)
- [ ] First-boot setup wizard in the GUI
- [ ] OTA update mechanism

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Can't SSH after base install | Pasted private key instead of public | Re-run base installer |
| Internet stops working | Static IP conflict | Re-run base installer, pick different IP |
| Dashboard not loading | Phalanx service not running | `sudo systemctl start phalanx` |
| Ads still showing | Router DNS not pointed at Pi | Change router DHCP DNS to Pi's IP |
| Port 53 permission denied | Not running as root | Service runs as root via systemd |
