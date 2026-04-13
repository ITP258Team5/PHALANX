# Project Phalanx

**Home Network Guardian** — A Raspberry Pi 4 appliance that blocks ads and trackers, monitors network traffic, and alerts non-technical users to suspicious activity via a simple web dashboard.

## How it works

Phalanx runs as a DNS proxy. Every device you point at it sends DNS queries through the Pi. Queries for known ad/tracker/malware domains get blocked (NXDOMAIN). Everything else forwards to Cloudflare/Google DNS. The dashboard shows what's connected, what's being blocked, and flags anomalies.

## Project structure

```
phalanx/
├── run.sh                   # Full setup (base + app, interactive)
├── config.env.example       # Network config template
├── .gitignore
│
├── base/                    # Layer 1: OS hardening
│   └── install.sh           #   Admin user, firewall, SSH, static IP
│
└── app/                     # Layer 2: Phalanx application
    ├── main.py              #   Entry point / orchestrator
    ├── requirements.txt     #   Python deps (aiohttp, psutil)
    ├── config/
    │   └── defaults.py      #   All tunables
    ├── core/
    │   ├── database.py      #   SQLite schema, versioned migrations
    │   ├── dns_proxy.py     #   Async UDP DNS proxy + LRU cache
    │   ├── blocklist.py     #   List download/parse, subscription gating
    │   ├── monitor.py       #   Per-device traffic + anomaly detection
    │   ├── subscription.py  #   Auth + subscription lifecycle
    │   └── access_control.py#   Role-based DB access (reader/writer/admin)
    ├── api/
    │   └── server.py        #   REST API + embedded fallback dashboard
    ├── gui/
    │   └── phalanx-gui.jsx  #   React dashboard (design prototype)
    ├── scripts/
    │   ├── install.sh       #   App installer (safe DNS switchover)
    │   └── phalanx.service  #   systemd unit
    └── tests/
        ├── test_dns_proxy.py    # 61 tests: DNS parsing, blocking, cache
        └── test_v2_schema.py    # 37 tests: triggers, views, access control
```

---

## Flash-to-test workflow

### What you need

- Raspberry Pi 4 (4GB)
- MicroSD card (16GB+)
- A separate PC/Mac for testing (on the same network)

### Step 1 — Flash Pi OS

Download [Raspberry Pi OS Lite](https://www.raspberrypi.com/software/) (64-bit). Flash it to the SD card with Raspberry Pi Imager. In the imager settings, enable SSH and set a password so you can connect headless.

Boot the Pi, find its IP (check your router's DHCP leases or run `ping raspberrypi.local`).

### Step 2 — Copy project to the Pi

From your PC:

```bash
scp -r phalanx/ pi@<PI_IP>:~/
ssh pi@<PI_IP>
```

### Step 3 — Base system setup (optional but recommended)

```bash
cd ~/phalanx
sudo bash base/install.sh
```

This creates a secure admin user, configures a static IP, sets up the firewall, and locks down SSH. Follow the prompts. Note the static IP it assigns — you'll use this for everything below.

If you want to skip this for quick testing, that's fine. Just use the Pi's current DHCP IP instead.

### Step 4 — Install Phalanx

```bash
sudo bash app/scripts/install.sh
```

This installs dependencies, deploys the app, starts the service, waits for the API to respond, downloads the blocklist (~200k domains), and only then switches the Pi's own DNS to localhost. If anything fails, it rolls back automatically.

You should see:

```
  ✅ Phalanx Installed and Running!

  Dashboard:   http://<PI_IP>
  Blocklist:   XXXXX domains blocked
```

### Step 5 — Verify from your test PC

**Do NOT change your router's DNS.** Instead, point only your test PC at the Pi so the rest of your network is unaffected.

**Mac:**
```bash
# Set DNS to the Pi
sudo networksetup -setdnsservers Wi-Fi <PI_IP>

# When done testing, reset to automatic
sudo networksetup -setdnsservers Wi-Fi empty
```

**Windows (PowerShell as admin):**
```powershell
# Set DNS to the Pi
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses <PI_IP>

# When done testing, reset to automatic
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
```

**Linux:**
```bash
# Temporary (resets on reboot)
sudo resolvectl dns wlan0 <PI_IP>

# Reset
sudo resolvectl revert wlan0
```

### Step 6 — Test blocking

From your test PC (with DNS pointed at the Pi):

```bash
# This should RESOLVE (legitimate site)
nslookup google.com
# Expected: returns an IP like 142.250.x.x

# This should be BLOCKED (ad domain)
nslookup ads.doubleclick.net
# Expected: NXDOMAIN or SERVFAIL (no IP returned)

# This should be BLOCKED (tracker)
nslookup tracking.example.com
# Expected: NXDOMAIN

# This should RESOLVE (not on blocklist)
nslookup github.com
# Expected: returns an IP
```

### Step 7 — Check the dashboard

Open `http://<PI_IP>` in your browser. You should see:

- Device count showing your test PC
- Blocked domain count increasing as you browse
- DNS query stats updating in real time
- Your test PC listed under "Connected devices"

### Step 8 — Switch back when done

Reset your test PC's DNS to automatic (commands above). The Pi keeps running — you can come back to it anytime by re-pointing DNS.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Sign in (email + password) |
| `POST` | `/api/auth/logout` | Sign out |
| `GET` | `/api/auth/status` | Auth + subscription status |
| `GET` | `/api/dashboard` | Full dashboard summary |
| `GET` | `/api/devices` | All seen devices |
| `POST` | `/api/devices/rename` | Rename a device `{ip, name}` |
| `GET` | `/api/alerts` | Recent alerts (`?include_low=true&limit=50`) |
| `GET` | `/api/alerts/grouped` | Alerts collapsed by group |
| `GET` | `/api/blocklist` | Blocklist stats + staleness |
| `POST` | `/api/blocklist/whitelist` | Allow a domain `{domain}` |
| `DELETE` | `/api/blocklist/whitelist` | Remove from whitelist `{domain}` |
| `POST` | `/api/blocklist/blacklist` | Force-block a domain `{domain}` |
| `GET` | `/api/diagnostics` | System memory, CPU, DNS proxy stats |

## Test suites

```bash
cd ~/phalanx/app

# DNS proxy logic (parsing, blocking, cache, matching)
python3 tests/test_dns_proxy.py      # 61 tests

# Schema, triggers, views, access control
python3 tests/test_v2_schema.py      # 37 tests
```

---

## What's done

- [x] DNS proxy engine (async UDP, LRU cache, parent-domain matching)
- [x] Blocklist manager (hosts + domain-list parsing, subscription gating, freeze-on-lapse)
- [x] Traffic monitor (batched stats, behavioral baselines, anomaly detection, alert suppression)
- [x] Subscription manager (ACTIVE → GRACE → LAPSED lifecycle)
- [x] SQLite schema v2 with versioned migrations
- [x] DB triggers (auto last_seen, alert-on-block, hourly rollup, anomaly-to-alert)
- [x] Read-only views + role-based access control (reader/writer/admin)
- [x] Sign-on audit log
- [x] REST API with all endpoints
- [x] Embedded HTML dashboard (live, auto-refresh)
- [x] React GUI prototype (login, dashboard, devices, alerts, blocklist management)
- [x] Base OS hardening (admin user, firewall, SSH lockdown, static IP)
- [x] Safe installer with DNS rollback on failure
- [x] systemd service with memory cap + security hardening
- [x] 98 passing tests

## What's remaining

- [ ] Build React GUI into `gui/dist/` (needs bundler pipeline; fallback HTML works now)
- [ ] Subscription cloud API backend (auth endpoint is a placeholder URL)
- [ ] Device auto-discovery (mDNS, DHCP lease parsing, MAC vendor lookup)
- [ ] Persist whitelist/blacklist to `user_overrides` table (currently in-memory)
- [ ] Sync blocklist sources to `blocklist_entries` table for "why was this blocked?"
- [ ] Device blocking from dashboard (drop DNS for blocked devices)
- [ ] HTTPS for dashboard (self-signed cert on first boot)
- [ ] First-boot setup wizard
- [ ] OTA update mechanism

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `nslookup` still resolves blocked domains | Test PC DNS not pointed at Pi | Re-run the DNS setup command for your OS |
| Dashboard won't load | Service not running | `sudo systemctl status phalanx` then check logs |
| Blocklist has 0 domains | Initial download failed | `sudo systemctl restart phalanx` (needs internet) |
| Port 53 permission denied | Not running as root | Service runs as root via systemd; manual runs need `sudo` |
| Pi lost internet after install | Phalanx crashed after DNS switch | `sudo cp /etc/resolv.conf.bak.phalanx /etc/resolv.conf` |
| SSH locked out after base install | SSH key paste went wrong | Mount SD card on another machine, fix `/etc/ssh/sshd_config` |

## Git

```bash
cd phalanx
git init
git add .
git commit -m "Phalanx v0.5 — DNS proxy, traffic monitor, dashboard, access control

- Async UDP DNS proxy with LRU cache and parent-domain matching
- Blocklist engine with subscription gating and freeze-on-lapse
- Per-device traffic monitoring with behavioral anomaly detection
- SQLite v2 schema: triggers, hourly rollups, role-based access control
- REST API with embedded dashboard + React GUI prototype
- OS hardening layer (firewall, SSH, static IP)
- Safe installer with automatic DNS rollback
- 98 passing tests"

git remote add origin https://github.com/<your-org>/phalanx.git
git branch -M main
git push -u origin main
```
