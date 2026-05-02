# Project Phalanx

A Raspberry Pi 4 appliance that blocks ads, trackers, and malicious domains at the network level. Non-technical users manage everything through a web dashboard — no command line needed after setup.

## How it works

Phalanx runs as a DNS proxy on your local network. Every device that routes DNS through the Pi has its queries checked against a blocklist of 130,000+ known ad, tracker, and malware domains. Blocked queries get an NXDOMAIN response (as if the domain doesn't exist). Legitimate queries are forwarded upstream via plain UDP DNS (DNS-over-HTTPS is available but off by default to avoid DNS loops when the Pi points at itself).

The dashboard at `http://<pi-ip>` shows real-time stats, live blocked/allowed query feeds, connected devices, and advanced reporting with threat intelligence, network discovery, and system health.

## Features

- **Ad and tracker blocking** — 130,000+ domains blocked out of the box via StevenBlack and anudeepND blocklists. Subscription tier adds Hagezi Pro and Ultimate for broader coverage.
- **Real-time dashboard** — Two-view interface accessible from the header: **Dashboard** (summary cards, live feeds, block/allow controls, engine toggle, connected devices) and **Advanced** (tabbed panels for deep analysis). Devices appear instantly with reverse DNS hostname resolution.
- **Advanced reporting** (Reporting tab) — Block rate, average latency, unique domains, active clients. Top blocked domains with bar charts, query type distribution, per-device breakdown, hourly activity chart, and full filterable query log showing domain, type, status, client, latency, and matched rule.
- **Threat intelligence** (Threats tab) — GeoIP lookup on blocked domains. Visual region-based threat map with color-coded continent cards, flag emojis, and proportional bars. Per-country breakdown with block counts. Detail table showing each blocked domain's IP, country, city, ISP, and block count.
- **Network device discovery** (Network tab) — nmap ping sweep or ARP table scan showing every device on the network with IP, MAC, vendor, and hostname.
- **Honeypot** (Honeypot tab) — Fake SSH (port 22), Telnet (port 23), HTTP (port 8888), and FTP (port 21) services that trap attackers. Captures credentials, payloads, and port scans. Sessions are classified by severity with full event timelines. High-severity intrusions auto-create alerts. Dashboard shows sessions, captured credentials, and event log.
- **System health** (System tab) — CPU, memory, disk, and Pi CPU temperature with progress bars. Live uptime and process memory.
- **Subscription system** — Cloud backend on Render handles registration, auth, and tier management. Free tier works forever; premium unlocks additional blocklists. Lapsed subscriptions freeze the last cached list — the device never bricks.
- **DHCP auto-configuration** — Optional dnsmasq setup makes the Pi the DHCP server. All devices automatically use Phalanx for DNS with zero per-device configuration. Fallback DNS (1.1.1.1) included in every lease.
- **Health watchdog** — Separate service monitors DNS health every 10 seconds. Auto-restarts Phalanx on failure. If unrecoverable, switches DHCP to advertise fallback DNS. Auto-restores when Phalanx recovers.
- **VPN support** — Tailscale integration for remote DNS protection and dashboard access from anywhere.
- **Security** — CSRF protection, rate limiting, input sanitization, role-based DB access, SSH hardening, firewall, dotfile blocking, generic auth errors.

## What you need

- Raspberry Pi 4 (4GB RAM)
- MicroSD card (16GB+)
- Power supply and ethernet cable (or Wi-Fi)
- A separate computer on the same network for testing

## Setup

### 1. Flash the Pi

Download [Raspberry Pi OS Lite](https://www.raspberrypi.com/software/) (64-bit). Flash it with Raspberry Pi Imager. In the imager settings, enable SSH, set a username and password, and configure Wi-Fi if not using ethernet.

Boot the Pi and find its IP (check your router's DHCP leases or try `ping raspberrypi.local`).

### 2. Copy the project to the Pi

```bash
scp -r phalanx/ <user>@<PI_IP>:~/
ssh <user>@<PI_IP>
```

### 3. Base system hardening (optional)

```bash
cd ~/phalanx
sudo bash base/install.sh
```

Creates a secure admin user, sets a static IP, configures the firewall, and locks SSH to key-only. Follow the prompts. Write down the static IP.

### 4. Install Phalanx

```bash
sudo bash app/scripts/install.sh
```

The installer runs 9 steps:
1. Installs system dependencies (Python, dnsutils, curl, nmap)
2. Deploys application to `/opt/phalanx`
3. Installs Python packages (aiohttp, psutil)
4. Configures systemd service
5. Starts Phalanx, verifies API is responding, downloads blocklists
6. Switches Pi's DNS to route through itself (only after service confirmed running)
7. Installs health watchdog
8. Verifies firewall
9. Optionally configures DHCP for plug-and-play mode

If anything fails, it rolls back automatically. Your Pi stays unchanged.

### 5. Set up the honeypot (recommended)

```bash
sudo bash /opt/phalanx/scripts/setup_honeypot_ports.sh
```

This moves real SSH from port 22 → port 2222, freeing port 22 for the honeypot. The script is safe — it listens on both ports simultaneously, verifies 2222 works, and only then removes port 22.

**After running this, always connect with:**
```bash
ssh <user>@<PI_IP> -p 2222
```

Then restart Phalanx so the honeypot claims port 22:
```bash
sudo systemctl restart phalanx
```

### 6. Point your test PC at the Pi

Change only your test PC's DNS to the Pi's IP:

**Mac:**
```bash
sudo networksetup -setdnsservers Wi-Fi <PI_IP>
# Reset: sudo networksetup -setdnsservers Wi-Fi empty
```

**Windows (PowerShell as admin):**
```powershell
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses <PI_IP>
# Reset: Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
```

**Linux:**
```bash
sudo resolvectl dns wlan0 <PI_IP>
# Reset: sudo resolvectl revert wlan0
```

### 7. Verify blocking

```bash
# Should RESOLVE (legitimate)
nslookup google.com

# Should be BLOCKED (ad domain)
nslookup ads.doubleclick.net
# Expected: NXDOMAIN

# Should RESOLVE
nslookup github.com
```

### 8. Open the dashboard

Go to `http://<PI_IP>` in your browser. The header bar has two views:

**Dashboard view** (default):
- **Summary cards** — devices online, blocklist size, total queries, total blocked
- **Block/Allow controls** — type a domain, click Block or Allow, takes effect instantly
- **Engine toggle** — pause/resume blocking from the header
- **Live blocked queries** — real-time feed with domain, client IP, and timestamp
- **Live allowed queries** — same for legitimate traffic
- **Connected devices** — every device routing DNS through Phalanx, with hostname and online status

**Advanced view** (click "Advanced" in the header) — five tabs:
- **Reporting** — block rate, avg latency, top blocked domains, query type distribution, per-device breakdown, hourly activity chart, full query log filterable by All/Blocked/Allowed
- **Threats** — click "Scan origins" to see a visual region-based threat map with continent cards, flag emojis, country breakdown, and a detail table with domain/country/city/ISP/blocks
- **Network** — click "Scan network" to discover all devices on the LAN with IP, MAC, vendor, and hostname
- **Honeypot** — sessions, captured credentials, event log, per-service stats
- **System** — CPU, memory, disk, temperature progress bars, uptime

### 9. Test the honeypot

If you ran the port swap in step 5, the honeypot is listening on port 22. From your test PC:

```bash
# This connects to the FAKE SSH (honeypot on port 22)
ssh root@<PI_IP>
# Type any password — it will say "Permission denied" and log everything
```

Open the dashboard → Advanced Reporting → scroll to the Honeypot panel. You'll see the session, the credentials you typed, and the event timeline in real time.

Your real SSH is on port 2222:
```bash
# This connects to the REAL SSH
ssh <user>@<PI_IP> -p 2222
```

## Optional setup

### Plug-and-play mode (DHCP)

```bash
sudo bash /opt/phalanx/scripts/setup_dhcp.sh
```

Makes the Pi the network's DHCP server. All devices automatically use Phalanx for DNS. Requires disabling your router's DHCP server.

### VPN remote access (Tailscale)

```bash
sudo bash /opt/phalanx/scripts/setup_vpn.sh
```

Adds Tailscale VPN. Devices on your Tailscale network get ad blocking even on public Wi-Fi or mobile data. Also enables remote dashboard access and SSH from anywhere.

### Subscription (premium blocklists)

The subscription backend runs at `https://phalanx-cloud.onrender.com` (private repo). To activate premium lists:

1. Register a user (requires invite code)
2. Set their tier to `standard` or `premium` in the admin panel
3. On the Pi, login and refresh:
```bash
curl -X POST http://127.0.0.1/api/auth/login -H "Content-Type: application/json" -H "X-Phalanx-Request: 1" -d "{\"email\":\"user@example.com\",\"password\":\"password\"}"
curl -X POST http://127.0.0.1/api/blocklist/refresh -H "Content-Type: application/json" -H "X-Phalanx-Request: 1"
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/dashboard` | Summary (devices, blocklist, queries, alerts) |
| `GET` | `/api/live` | Real-time blocked/allowed query feeds |
| `GET` | `/api/report` | Advanced reporting (top domains, per-client, hourly, full log) |
| `GET` | `/api/geoip` | Threat intelligence (GeoIP on blocked domains) |
| `GET` | `/api/network/scan` | Network device discovery (nmap/ARP) |
| `GET` | `/api/diagnostics` | System health (CPU, memory, disk, temperature) |
| `GET` | `/api/honeypot` | Honeypot stats (sessions, credentials, events) |
| `GET` | `/api/honeypot/session/{id}` | Events for a specific honeypot session |
| `GET` | `/api/devices` | Connected device list |
| `POST` | `/api/devices/rename` | Rename a device |
| `GET` | `/api/alerts` | Security alerts |
| `GET` | `/api/blocklist` | Blocklist stats |
| `POST` | `/api/blocklist/blacklist` | Block a domain |
| `POST` | `/api/blocklist/whitelist` | Allow a domain |
| `DELETE` | `/api/blocklist/whitelist` | Remove from whitelist |
| `POST` | `/api/blocklist/refresh` | Trigger blocklist update |
| `GET` | `/api/engine` | Blocking engine status |
| `POST` | `/api/engine/toggle` | Pause/resume blocking |
| `POST` | `/api/auth/login` | Sign in |
| `POST` | `/api/auth/logout` | Sign out |
| `GET` | `/api/auth/status` | Auth + subscription status |

All POST requests require the header `X-Phalanx-Request: 1` (CSRF protection).

## Tests

```bash
cd ~/phalanx/app
python3 tests/test_dns_proxy.py     # 70 tests
python3 tests/test_v2_schema.py     # 37 tests
```

## Project structure

```
phalanx/
├── run.sh                        # Full setup (base + app)
├── config.env.example            # Network config template
├── base/
│   └── install.sh                # OS hardening
└── app/
    ├── main.py                   # Entry point
    ├── requirements.txt          # Python deps
    ├── config/
    │   └── defaults.py           # All tunables
    ├── core/
    │   ├── database.py           # SQLite schema + migrations (v2)
    │   ├── dns_proxy.py          # DNS proxy + DoH + cache + engine toggle
    │   ├── blocklist.py          # Blocklist management + subscription gating
    │   ├── monitor.py            # Traffic monitoring + anomaly detection
    │   ├── subscription.py       # Auth + subscription lifecycle
    │   ├── access_control.py     # Role-based DB access
    │   ├── honeypot.py           # Fake service listeners (SSH, HTTP, Telnet, FTP)
    │   └── net_tools.py          # GeoIP, nmap scanning, network tools
    ├── api/
    │   └── server.py             # REST API + dashboard
    ├── gui/
    │   └── phalanx-gui.jsx       # React GUI prototype
    ├── scripts/
    │   ├── install.sh            # App installer (9-step, safe rollback)
    │   ├── phalanx.service       # systemd unit
    │   ├── phalanx-watchdog.service # Watchdog systemd unit
    │   ├── watchdog.py           # DNS health monitor + failsafe
    │   ├── setup_dhcp.sh         # DHCP auto-configuration
    │   ├── setup_vpn.sh          # Tailscale VPN setup
    │   ├── setup_honeypot_ports.sh # SSH port swap (22→2222 for honeypot)
    │   ├── cleanup_logs.py       # Daily log/DB rotation (cron)
    │   ├── parse_dns_logs.py     # DNS log backfill parser
    │   └── update_blocklist.sh   # Weekly blocklist refresh (cron)
    └── tests/
        ├── test_dns_proxy.py     # 70 tests
        └── test_v2_schema.py     # 37 tests
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `nslookup` still resolves blocked domains | Test PC DNS not pointed at Pi |
| Dashboard won't load | `sudo systemctl status phalanx` |
| Blocklist shows 0 domains | `sudo systemctl restart phalanx` (needs internet) |
| Pi lost internet after install | `sudo cp /etc/resolv.conf.bak.phalanx /etc/resolv.conf` |
| Port 53 permission denied | Must run as root (systemd handles this) |
| No queries in dashboard | No devices routing DNS through the Pi yet |
| GeoIP shows no data | Click "Scan origins" after generating some blocked queries |
| Network scan empty | Install nmap: `sudo apt install nmap` |
| DoH errors in log | Expected if Pi DNS points at itself; uses UDP fallback |
| Can't SSH after port swap | Use port 2222: `ssh user@<PI_IP> -p 2222` |
| Locked out of SSH entirely | Connect monitor + keyboard, `sudo cp /etc/ssh/sshd_config.bak.phalanx /etc/ssh/sshd_config && sudo systemctl restart ssh` |
| Honeypot not catching anything | Run `sudo systemctl restart phalanx` after the port swap. Verify with `ssh root@<PI_IP>` (port 22). |
| Port 22 already in use | The SSH port swap didn't run. Run `sudo bash /opt/phalanx/scripts/setup_honeypot_ports.sh` first. |
