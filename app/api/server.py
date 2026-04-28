"""
Phalanx API Server

Lightweight HTTP API served via aiohttp.

Key fix: The device must be usable on first boot before a subscription
exists. The auth middleware now allows access in "setup mode" (no user
has ever logged in) so the GUI loads and the user can sign in or use
the device with free blocklists only.
"""

import json
import logging
import os
import re
import time
from collections import defaultdict
from html import escape as html_escape
from pathlib import Path

from aiohttp import web

import config

logger = logging.getLogger("phalanx.api")

GUI_DIR = config.BASE_DIR / "gui" / "dist"


# ── Input validation ──

# Matches valid domain names (letters, digits, hyphens, dots)
_DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$")

# Matches valid IPv4
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Max length for freeform text fields
_MAX_NAME_LEN = 64
_MAX_EMAIL_LEN = 254
_MAX_DOMAIN_LEN = 253


def sanitize_text(value: str, max_len: int = _MAX_NAME_LEN) -> str:
    """Strip HTML tags and limit length. For device names, user labels, etc."""
    if not isinstance(value, str):
        return ""
    # Strip any HTML tags
    clean = re.sub(r"<[^>]*>", "", value)
    # Escape remaining special chars
    clean = html_escape(clean, quote=True)
    return clean[:max_len].strip()


def validate_domain(domain: str) -> str | None:
    """Validate and normalize a domain name. Returns cleaned domain or None."""
    if not isinstance(domain, str):
        return None
    domain = domain.strip().lower().strip(".")
    if not domain or len(domain) > _MAX_DOMAIN_LEN:
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain


def validate_ip(ip: str) -> str | None:
    """Validate an IPv4 address. Returns cleaned IP or None."""
    if not isinstance(ip, str):
        return None
    ip = ip.strip()
    if not _IPV4_RE.match(ip):
        return None
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        return None
    return ip


class RateLimiter:
    """Simple per-IP rate limiter for auth endpoints."""
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._max = max_attempts
        self._window = window_seconds

    def check(self, key: str) -> bool:
        """Returns True if the request is allowed, False if rate-limited."""
        now = time.time()
        attempts = self._attempts[key]
        # Prune old attempts
        self._attempts[key] = [t for t in attempts if now - t < self._window]
        if len(self._attempts[key]) >= self._max:
            return False
        self._attempts[key].append(now)
        return True


_login_limiter = RateLimiter(max_attempts=5, window_seconds=300)


def create_app(subscription_mgr, blocklist_mgr, traffic_monitor) -> web.Application:
    app = web.Application()
    app["sub"] = subscription_mgr
    app["blocklist"] = blocklist_mgr
    app["monitor"] = traffic_monitor

    # ── Auth middleware ──
    # Allows access when:
    #   1. Hitting /api/auth/* endpoints (login, status)
    #   2. No user has ever logged in (setup mode — device works with free lists)
    #   3. User is authenticated
    @web.middleware
    async def auth_middleware(request: web.Request, handler):
        # Always allow auth endpoints and static files
        if request.path.startswith("/api/auth") or not request.path.startswith("/api/"):
            return await handler(request)

        sub = request.app["sub"]

        # Setup mode: no user has ever configured the device.
        # Allow full API access so the dashboard works out of the box.
        # Free blocklists are active; subscription features are gated elsewhere.
        if sub.user_id is None and not sub.is_authenticated:
            return await handler(request)

        # Normal mode: require auth
        if not sub.is_authenticated:
            return web.json_response(
                {"error": "Session expired. Please sign in again."},
                status=401,
            )

        return await handler(request)

    app.middlewares.append(auth_middleware)

    # ── Auth routes ──

    async def login(request: web.Request):
        client_ip = request.remote or "unknown"
        if not _login_limiter.check(client_ip):
            return web.json_response(
                {"error": "Too many login attempts. Try again in a few minutes."},
                status=429,
            )
        body = await request.json()
        email = sanitize_text(body.get("email", ""), max_len=_MAX_EMAIL_LEN)
        password = body.get("password", "")
        if not email or not password:
            return web.json_response({"error": "Email and password required"}, status=400)
        result = await request.app["sub"].authenticate(email, password)
        status = 200 if result["success"] else 401
        return web.json_response(result, status=status)

    async def logout(request: web.Request):
        request.app["sub"].logout()
        return web.json_response({"success": True})

    async def auth_status(request: web.Request):
        return web.json_response(request.app["sub"].get_status_summary())

    # ── Dashboard ──

    async def dashboard_summary(request: web.Request):
        monitor = request.app["monitor"]
        blocklist = request.app["blocklist"]
        sub = request.app["sub"]

        devices = monitor.get_device_summary()
        alerts = monitor.get_alerts(limit=10)
        staleness = blocklist.staleness_warning()

        return web.json_response({
            "devices": {
                "total": len(devices),
                "online": sum(
                    1 for d in devices
                    if time.time() - d.get("last_seen", 0) < 300
                ),
                "list": devices,
            },
            "blocklist": {
                "total_domains": blocklist.domain_count,
                "sources": blocklist.metadata,
                "staleness_warning": staleness,
            },
            "alerts": {
                "high": sum(1 for a in alerts if a.get("severity") == "high"),
                "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
                "recent": alerts[:5],
            },
            "subscription": sub.get_status_summary(),
            "dns": _get_dns_stats(request),
        })

    # ── Devices ──

    async def device_list(request: web.Request):
        devices = request.app["monitor"].get_device_summary()
        return web.json_response({"devices": devices})

    async def device_rename(request: web.Request):
        body = await request.json()
        ip = validate_ip(body.get("ip", ""))
        name = sanitize_text(body.get("name", ""))
        if not ip:
            return web.json_response({"error": "Invalid IP address"}, status=400)
        if not name:
            return web.json_response({"error": "Name is required (max 64 chars, no HTML)"}, status=400)
        request.app["monitor"].set_device_name(ip, name)
        return web.json_response({"success": True})

    # ── Alerts ──

    async def alert_list(request: web.Request):
        include_low = request.query.get("include_low", "false") == "true"
        try:
            limit = min(int(request.query.get("limit", "50")), 500)
        except ValueError:
            limit = 50
        alerts = request.app["monitor"].get_alerts(limit=limit, include_low=include_low)
        return web.json_response({"alerts": alerts})

    async def alert_grouped(request: web.Request):
        try:
            limit = min(int(request.query.get("limit", "20")), 200)
        except ValueError:
            limit = 20
        alerts = request.app["monitor"].get_grouped_alerts(limit=limit)
        return web.json_response({"alerts": alerts})

    # ── Blocklist ──

    async def blocklist_status(request: web.Request):
        bl = request.app["blocklist"]
        return web.json_response({
            "total_domains": bl.domain_count,
            "sources": bl.metadata,
            "staleness_warning": bl.staleness_warning(),
        })

    async def blocklist_whitelist_add(request: web.Request):
        body = await request.json()
        domain = validate_domain(body.get("domain", ""))
        if not domain:
            return web.json_response({"error": "Invalid domain name"}, status=400)
        request.app["blocklist"].add_whitelist(domain)
        return web.json_response({"success": True, "domain": domain, "action": "whitelisted"})

    async def blocklist_whitelist_remove(request: web.Request):
        body = await request.json()
        domain = validate_domain(body.get("domain", ""))
        if not domain:
            return web.json_response({"error": "Invalid domain name"}, status=400)
        request.app["blocklist"].remove_whitelist(domain)
        return web.json_response({"success": True, "domain": domain, "action": "removed_from_whitelist"})

    async def blocklist_blacklist_add(request: web.Request):
        body = await request.json()
        domain = validate_domain(body.get("domain", ""))
        if not domain:
            return web.json_response({"error": "Invalid domain name"}, status=400)
        request.app["blocklist"].add_blacklist(domain)
        return web.json_response({"success": True, "domain": domain, "action": "blacklisted"})

    # ── Diagnostics ──

    async def diagnostics(request: web.Request):
        try:
            import psutil
            proc = psutil.Process(os.getpid())
            mem = proc.memory_info()
            system_info = {
                "memory_rss_mb": round(mem.rss / 1024 / 1024, 1),
                "memory_vms_mb": round(mem.vms / 1024 / 1024, 1),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "uptime_seconds": round(time.time() - proc.create_time()),
            }
        except ImportError:
            system_info = {"note": "psutil not installed"}

        return web.json_response({
            "system": system_info,
            "dns": _get_dns_stats(request),
            "blocklist": {
                "total_domains": request.app["blocklist"].domain_count,
            },
        })

    def _get_dns_stats(request):
        dns_proto = request.app.get("dns_protocol")
        return dns_proto.stats if dns_proto else {}

    # ── Engine toggle ──

    async def engine_status(request: web.Request):
        """Get current blocking engine status."""
        dns_proto = request.app.get("dns_protocol")
        return web.json_response({
            "blocking_enabled": dns_proto.blocking_enabled if dns_proto else False,
            "doh_enabled": config.DOH_ENABLED,
        })

    async def engine_toggle(request: web.Request):
        """Enable or disable the blocking engine at runtime."""
        body = await request.json()
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return web.json_response({"error": "Field 'enabled' must be true or false"}, status=400)

        dns_proto = request.app.get("dns_protocol")
        if not dns_proto:
            return web.json_response({"error": "DNS proxy not running"}, status=503)

        dns_proto.set_blocking(enabled)
        return web.json_response({
            "success": True,
            "blocking_enabled": dns_proto.blocking_enabled,
        })

    # ── Blocklist refresh ──

    async def blocklist_refresh(request: web.Request):
        """Manually trigger a blocklist update."""
        bl = request.app["blocklist"]
        sub = request.app["sub"]
        is_active = sub.is_subscription_active
        results = await bl.update(subscription_active=is_active)

        # Hot-swap into DNS proxy
        dns_proto = request.app.get("dns_protocol")
        if dns_proto:
            dns_proto.blocklist = bl.active_set

        return web.json_response({
            "success": True,
            "total_domains": bl.domain_count,
            "sources": results,
        })

    # ── GUI serving ──
    # Serve index.html for all non-API routes (SPA fallback)

    async def serve_gui(request: web.Request):
        """Serve the GUI. Falls back to index.html for SPA routing."""
        # Try the exact file first
        file_path = GUI_DIR / request.path.lstrip("/")
        if file_path.is_file():
            return web.FileResponse(file_path)

        # SPA fallback
        index = GUI_DIR / "index.html"
        if index.is_file():
            return web.FileResponse(index)

        # No GUI built — return a helpful message
        return web.Response(
            text=_FALLBACK_HTML,
            content_type="text/html",
        )

    # ── Register routes ──

    app.router.add_post("/api/auth/login", login)
    app.router.add_post("/api/auth/logout", logout)
    app.router.add_get("/api/auth/status", auth_status)

    app.router.add_get("/api/dashboard", dashboard_summary)

    app.router.add_get("/api/devices", device_list)
    app.router.add_post("/api/devices/rename", device_rename)

    app.router.add_get("/api/alerts", alert_list)
    app.router.add_get("/api/alerts/grouped", alert_grouped)

    app.router.add_get("/api/blocklist", blocklist_status)
    app.router.add_post("/api/blocklist/whitelist", blocklist_whitelist_add)
    app.router.add_delete("/api/blocklist/whitelist", blocklist_whitelist_remove)
    app.router.add_post("/api/blocklist/blacklist", blocklist_blacklist_add)
    app.router.add_post("/api/blocklist/refresh", blocklist_refresh)

    app.router.add_get("/api/engine", engine_status)
    app.router.add_post("/api/engine/toggle", engine_toggle)

    app.router.add_get("/api/diagnostics", diagnostics)

    # GUI catch-all (must be last)
    app.router.add_get("/{path:.*}", serve_gui)

    return app


# ── Fallback HTML when no GUI build exists ──
# This is a minimal working dashboard so the device is testable
# even before the React GUI is built and deployed.

_FALLBACK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phalanx — Home Network Guardian</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0f1117; color: #e2e4e9; }
  .header { padding: 20px 24px; background: #161822; border-bottom: 1px solid #2a2d3a; display: flex; align-items: center; gap: 14px; }
  .logo { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #3b82f6, #06b6d4); display: flex; align-items: center; justify-content: center; font-weight: 700; color: #fff; font-size: 18px; }
  .title { font-size: 17px; font-weight: 700; }
  .subtitle { font-size: 11px; color: #6b7280; }
  .container { max-width: 1000px; margin: 0 auto; padding: 24px; padding-bottom: 60px; }
  .nav { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
  .nav button { background: #181b25; color: #9ca3af; border: 1px solid #2a2d3a; border-radius: 10px; padding: 9px 13px; cursor: pointer; font-weight: 600; }
  .nav button.active { background: #1d355f; color: #60a5fa; border-color: #3b82f6; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .card { background: #181b25; border-radius: 14px; padding: 20px; border: 1px solid #2a2d3a; }
  .card-label { font-size: 11px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.8px; }
  .card-value { font-size: 24px; font-weight: 700; margin-top: 6px; font-family: monospace; }
  .card-sub { font-size: 12px; color: #6b7280; margin-top: 4px; }
  .section { margin-top: 24px; }
  .section-title { font-size: 14px; font-weight: 700; color: #9ca3af; margin-bottom: 8px; }
  .section-help { font-size: 13px; color: #6b7280; margin-bottom: 12px; }
  .device, .alert, .row-box { background: #181b25; border: 1px solid #2a2d3a; border-radius: 12px; padding: 14px 18px; margin-bottom: 8px; }
  .device { display: flex; align-items: center; gap: 14px; }
  .device-name { font-size: 14px; font-weight: 600; }
  .device-meta { font-size: 11px; color: #6b7280; margin-top: 2px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; margin-left: auto; }
  .dot-green { background: #22c55e; box-shadow: 0 0 8px #22c55e66; }
  .dot-gray { background: #6b7280; }
  .alert { border-left: 3px solid; }
  .alert-high, .alert-critical { border-color: #ef4444; }
  .alert-medium { border-color: #f59e0b; }
  .alert-low { border-color: #22c55e; }
  .alert-sev { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-bottom: 4px; background: #111827; }
  .alert-msg { font-size: 13px; color: #9ca3af; }
  .loading { text-align: center; padding: 24px; color: #6b7280; }
  .error { color: #ef4444; text-align: center; padding: 20px; }
  input { padding: 10px 12px; border-radius: 10px; border: 1px solid #2a2d3a; background: #0f1117; color: #e2e4e9; }
  button.action { padding: 10px 14px; border-radius: 10px; border: none; cursor: pointer; font-weight: 700; background: #3b82f6; color: white; }
  button.danger { background: #7f1d1d; color: #fecaca; }
  table { width: 100%; border-collapse: collapse; background: #181b25; border: 1px solid #2a2d3a; border-radius: 12px; overflow: hidden; }
  th, td { padding: 12px; border-bottom: 1px solid #2a2d3a; text-align: left; font-size: 13px; }
  th { color: #9ca3af; font-size: 11px; text-transform: uppercase; letter-spacing: .6px; }
  .bar-bg { height: 10px; background: #0f1117; border-radius: 8px; overflow: hidden; margin: 6px 0 12px; }
  .bar-blue { height: 100%; background: #3b82f6; }
  .bar-green { height: 100%; background: #22c55e; }
  #status-bar { padding: 8px 24px; font-size: 12px; color: #6b7280; background: #161822; border-top: 1px solid #2a2d3a; position: fixed; bottom: 0; width: 100%; }
  .hidden { display: none; }
  @media (max-width: 800px) { .cards { grid-template-columns: 1fr 1fr; } }
</style>
</head>
<body>
<div class="header">
  <div class="logo">P</div>
  <div>
    <div class="title">Project Phalanx</div>
    <div class="subtitle">Home Network Guardian</div>
  </div>
</div>

<div class="container">
  <div class="nav">
    <button onclick="showTab('dashboard')" id="nav-dashboard" class="active">Dashboard</button>
    <button onclick="showTab('devices')" id="nav-devices">Connected Devices</button>
    <button onclick="showTab('threats')" id="nav-threats">Threats</button>
    <button onclick="showTab('bandwidth')" id="nav-bandwidth">Bandwidth</button>
    <button onclick="showTab('blocklist')" id="nav-blocklist">Blocklist</button>
  </div>

  <div id="tab-dashboard">
    <div class="cards">
      <div class="card">
        <div class="card-label">Devices online</div>
        <div class="card-value" id="devices-count" style="color:#22c55e;">—</div>
        <div class="card-sub" id="devices-sub">Loading...</div>
      </div>
      <div class="card">
        <div class="card-label">Domains blocked</div>
        <div class="card-value" id="blocked-count" style="color:#3b82f6;">—</div>
        <div class="card-sub" id="blocked-sub">Loading...</div>
      </div>
      <div class="card">
        <div class="card-label">DNS queries</div>
        <div class="card-value" id="dns-count" style="color:#a78bfa;">—</div>
        <div class="card-sub" id="dns-sub">Loading...</div>
      </div>
      <div class="card">
        <div class="card-label">System Health</div>
        <div class="card-value" id="system-health" style="color:#22c55e;">CPU —</div>
        <div class="card-sub" id="system-sub">RAM — · Temp —</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Connected Devices</div>
      <div class="section-help">Shows devices detected on the local network.</div>
      <div id="device-list"><div class="loading">Loading...</div></div>
    </div>

    <div class="section">
      <div class="section-title">Recent Alerts</div>
      <div id="alert-list"><div class="loading">Loading...</div></div>
    </div>
  </div>

  <div id="tab-devices" class="hidden">
    <div class="section-title">Connected Devices</div>
    <div class="section-help">Shows devices detected on the local network, including their IP address, status, and last seen time.</div>
    <div id="device-list-full"><div class="loading">Loading...</div></div>
  </div>

  <div id="tab-threats" class="hidden">
    <div class="section-title">Threat Intelligence Map</div>
    <div class="section-help">Shows where blocked or suspicious domains are coming from when Geo-IP data is available.</div>
    <div id="threat-map"><div class="loading">No threat location data available yet.</div></div>

    <div class="section">
      <div class="section-title">Threat Intelligence Table</div>
      <table>
        <thead>
          <tr><th>Domain</th><th>Device</th><th>Country</th><th>Severity</th></tr>
        </thead>
        <tbody id="threat-table">
          <tr><td colspan="4">No threat intelligence records available yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div id="tab-bandwidth" class="hidden">
    <div class="section-title">Network Bandwidth Monitoring</div>
    <div class="section-help">Shows daily upload and download totals from the local network when bandwidth data is available.</div>
    <div id="bandwidth-list"><div class="loading">No bandwidth data available yet.</div></div>
  </div>

  <div id="tab-blocklist" class="hidden">
    <div class="section-title">Website Blocking Controls</div>
    <div class="section-help">Enter a website like example.com to block or allow it.</div>

    <div class="row-box">
      <div class="section-title">Block a website</div>
      <input id="blockInput" placeholder="example.com">
      <button class="action danger" onclick="blockDomain()">Block Website</button>
      <div class="section-help" style="margin-top:8px;">Always block this website.</div>
    </div>

    <div class="row-box">
      <div class="section-title">Allow a website</div>
      <input id="allowInput" placeholder="example.com">
      <button class="action" onclick="allowDomain()">Allow Website</button>
      <div class="section-help" style="margin-top:8px;">Always allow this website.</div>
    </div>
  </div>
</div>

<div id="status-bar">Connecting to Phalanx...</div>

<script>
let lastData = null;

function showTab(name) {
  ['dashboard','devices','threats','bandwidth','blocklist'].forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('hidden', t !== name);
    document.getElementById('nav-' + t).classList.toggle('active', t === name);
  });
}

async function refresh() {
  try {
    const res = await fetch('/api/dashboard');
    if (!res.ok) throw new Error('API ' + res.status);
    const d = await res.json();
    lastData = d;

    document.getElementById('devices-count').textContent = d.devices.online + ' / ' + d.devices.total;
    document.getElementById('devices-sub').textContent = d.devices.online === d.devices.total ? 'All devices are connected' : 'Some devices may be offline';

    document.getElementById('blocked-count').textContent = d.blocklist.total_domains.toLocaleString();
    document.getElementById('blocked-sub').textContent = 'In active blocklist';

    const dns = d.dns || {};
    document.getElementById('dns-count').textContent = (dns.queries || 0).toLocaleString();
    document.getElementById('dns-sub').textContent = (dns.blocked || 0) + ' blocked, ' + (dns.cached || 0) + ' cached';

    const system = d.system || d.health || (d.diagnostics && d.diagnostics.system) || {};
    const cpu = system.cpu_percent ?? system.cpu ?? '—';
    const ram = system.ram_percent ?? system.memory_percent ?? '—';
    const temp = system.temperature_c ?? system.temp_c ?? system.temperature ?? '—';
    document.getElementById('system-health').textContent = 'CPU ' + cpu + (cpu === '—' ? '' : '%');
    document.getElementById('system-sub').textContent = 'RAM ' + ram + (ram === '—' ? '' : '%') + ' · Temp ' + temp + (temp === '—' ? '' : '°C');

    renderDevices(d);
    renderAlerts(d);
    renderThreats(d);
    renderBandwidth(d);

    const sub = d.subscription || {};
    let statusText = 'Phalanx running';
    if (sub.status === 'active') statusText += ' · Subscription active';
    else if (sub.status === 'grace') statusText += ' · Subscription expiring in ' + sub.days_until_freeze + ' days';
    else if (sub.status === 'lapsed') statusText += ' · Blocklists frozen';
    else statusText += ' · Free mode';
    statusText += ' · ' + d.blocklist.total_domains.toLocaleString() + ' domains blocked';
    document.getElementById('status-bar').textContent = statusText;

  } catch (e) {
    document.getElementById('status-bar').textContent = 'Error: ' + e.message;
  }
}

function renderDevices(d) {
  const html = d.devices.list && d.devices.list.length > 0
    ? d.devices.list.map(dev => {
        const online = (Date.now()/1000 - dev.last_seen) < 300;
        return '<div class="device">' +
          '<div><div class="device-name">' + esc(dev.name) + '</div>' +
          '<div class="device-meta">' + esc(dev.ip) + ' · ' + esc(dev.device_type) + '</div></div>' +
          '<div class="dot ' + (online ? 'dot-green' : 'dot-gray') + '"></div></div>';
      }).join('')
    : '<div class="loading">No devices detected yet.</div>';
  document.getElementById('device-list').innerHTML = html;
  document.getElementById('device-list-full').innerHTML = html;
}

function renderAlerts(d) {
  const alerts = (d.alerts && d.alerts.recent) || [];
  const al = document.getElementById('alert-list');
  if (alerts.length > 0) {
    al.innerHTML = alerts.map(a =>
      '<div class="alert alert-' + esc(a.severity) + '">' +
      '<span class="alert-sev">' + esc((a.severity || 'low').toUpperCase()) + '</span> ' +
      '<strong>' + esc(a.device_name || a.device_ip || 'Unknown device') + '</strong>' +
      '<div class="alert-msg">' + esc(a.message || '') + '</div></div>'
    ).join('');
  } else {
    al.innerHTML = '<div class="loading">No alerts. Your network looks clean.</div>';
  }
}

function renderThreats(d) {
  const alerts = (d.alerts && d.alerts.recent) || [];
  const rows = ((d.threat_intelligence && d.threat_intelligence.items) || (d.threats && d.threats.items) || alerts).map((item, i) => ({
    domain: item.domain || item.hostname || item.message || 'Unknown domain',
    device: item.device_name || item.device_ip || 'Unknown device',
    country: item.country || item.country_name || item.geo_country || 'Unknown',
    severity: item.severity || 'medium'
  }));

  const countries = {};
  rows.forEach(r => countries[r.country] = (countries[r.country] || 0) + 1);

  document.getElementById('threat-map').innerHTML = Object.keys(countries).length
    ? Object.entries(countries).map(([country, count]) =>
        '<div class="row-box"><strong>' + esc(country) + '</strong><div class="section-help">' + count + ' blocked request(s)</div></div>'
      ).join('')
    : '<div class="loading">No threat location data available yet.</div>';

  document.getElementById('threat-table').innerHTML = rows.length
    ? rows.map(r => '<tr><td>' + esc(r.domain) + '</td><td>' + esc(r.device) + '</td><td>' + esc(r.country) + '</td><td>' + esc(r.severity) + '</td></tr>').join('')
    : '<tr><td colspan="4">No threat intelligence records available yet.</td></tr>';
}

function renderBandwidth(d) {
  const rows = ((d.bandwidth && d.bandwidth.daily) || (d.network && d.network.bandwidth_daily) || (d.bandwidth && d.bandwidth.items) || []).map((item, i) => ({
    day: item.day || item.date || 'Day ' + (i + 1),
    upload: item.upload_mb ?? item.upload ?? 0,
    download: item.download_mb ?? item.download ?? 0
  }));

  const max = Math.max(1, ...rows.map(r => Math.max(r.upload, r.download)));

  document.getElementById('bandwidth-list').innerHTML = rows.length
    ? rows.map(r => {
        const downWidth = Math.round((r.download / max) * 100);
        const upWidth = Math.round((r.upload / max) * 100);
        return '<div class="row-box"><strong>' + esc(r.day) + '</strong>' +
          '<div class="section-help">Download: ' + esc(r.download) + ' MB</div>' +
          '<div class="bar-bg"><div class="bar-blue" style="width:' + downWidth + '%"></div></div>' +
          '<div class="section-help">Upload: ' + esc(r.upload) + ' MB</div>' +
          '<div class="bar-bg"><div class="bar-green" style="width:' + upWidth + '%"></div></div></div>';
      }).join('')
    : '<div class="loading">No bandwidth data available yet.</div>';
}

async function blockDomain() {
  const domain = document.getElementById('blockInput').value.trim();
  if (!domain) return alert('Enter a website like example.com');
  await fetch('/api/blocklist/blacklist', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({domain})
  });
  document.getElementById('blockInput').value = '';
  alert('Website blocked: ' + domain);
  refresh();
}

async function allowDomain() {
  const domain = document.getElementById('allowInput').value.trim();
  if (!domain) return alert('Enter a website like example.com');
  await fetch('/api/blocklist/whitelist', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({domain})
  });
  document.getElementById('allowInput').value = '';
  alert('Website allowed: ' + domain);
  refresh();
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""