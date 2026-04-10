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
import time
from pathlib import Path

from aiohttp import web

import config

logger = logging.getLogger("phalanx.api")

GUI_DIR = config.BASE_DIR / "gui" / "dist"


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
        body = await request.json()
        email = body.get("email", "")
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
        ip = body.get("ip", "")
        name = body.get("name", "")
        if not ip or not name:
            return web.json_response({"error": "ip and name required"}, status=400)
        request.app["monitor"].set_device_name(ip, name)
        return web.json_response({"success": True})

    # ── Alerts ──

    async def alert_list(request: web.Request):
        include_low = request.query.get("include_low", "false") == "true"
        limit = int(request.query.get("limit", "50"))
        alerts = request.app["monitor"].get_alerts(limit=limit, include_low=include_low)
        return web.json_response({"alerts": alerts})

    async def alert_grouped(request: web.Request):
        limit = int(request.query.get("limit", "20"))
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
        domain = body.get("domain", "")
        if not domain:
            return web.json_response({"error": "domain required"}, status=400)
        request.app["blocklist"].add_whitelist(domain)
        return web.json_response({"success": True, "domain": domain, "action": "whitelisted"})

    async def blocklist_whitelist_remove(request: web.Request):
        body = await request.json()
        domain = body.get("domain", "")
        request.app["blocklist"].remove_whitelist(domain)
        return web.json_response({"success": True, "domain": domain, "action": "removed_from_whitelist"})

    async def blocklist_blacklist_add(request: web.Request):
        body = await request.json()
        domain = body.get("domain", "")
        if not domain:
            return web.json_response({"error": "domain required"}, status=400)
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
  .container { max-width: 800px; margin: 0 auto; padding: 24px; }
  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
  .card { background: #181b25; border-radius: 14px; padding: 20px; border: 1px solid #2a2d3a; }
  .card-label { font-size: 11px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.8px; }
  .card-value { font-size: 28px; font-weight: 700; margin-top: 6px; font-family: 'JetBrains Mono', monospace; }
  .card-sub { font-size: 12px; color: #6b7280; margin-top: 4px; }
  .section-title { font-size: 14px; font-weight: 600; color: #9ca3af; margin-bottom: 12px; }
  .device { background: #181b25; border: 1px solid #2a2d3a; border-radius: 12px; padding: 14px 18px; margin-bottom: 8px; display: flex; align-items: center; gap: 14px; }
  .device-name { font-size: 14px; font-weight: 600; }
  .device-meta { font-size: 11px; color: #6b7280; margin-top: 2px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; margin-left: auto; }
  .dot-green { background: #22c55e; box-shadow: 0 0 8px #22c55e66; }
  .dot-gray { background: #6b7280; }
  .alert { background: #181b25; border-radius: 12px; padding: 14px 18px; margin-bottom: 8px; border-left: 3px solid; }
  .alert-high { border-color: #ef4444; }
  .alert-medium { border-color: #f59e0b; }
  .alert-low { border-color: #22c55e; }
  .alert-sev { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-bottom: 4px; }
  .alert-msg { font-size: 13px; color: #9ca3af; }
  .loading { text-align: center; padding: 40px; color: #6b7280; }
  .error { color: #ef4444; text-align: center; padding: 20px; }
  #status-bar { padding: 8px 24px; font-size: 12px; color: #6b7280; background: #161822; border-top: 1px solid #2a2d3a; position: fixed; bottom: 0; width: 100%; }
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
  <div class="cards">
    <div class="card">
      <div class="card-label">Devices online</div>
      <div class="card-value" id="devices-count" style="color: #22c55e;">—</div>
      <div class="card-sub" id="devices-sub">Loading...</div>
    </div>
    <div class="card">
      <div class="card-label">Domains blocked</div>
      <div class="card-value" id="blocked-count" style="color: #3b82f6;">—</div>
      <div class="card-sub" id="blocked-sub">Loading...</div>
    </div>
    <div class="card">
      <div class="card-label">DNS queries</div>
      <div class="card-value" id="dns-count" style="color: #a78bfa;">—</div>
      <div class="card-sub" id="dns-sub">Loading...</div>
    </div>
  </div>

  <div class="section-title">Connected devices</div>
  <div id="device-list"><div class="loading">Loading...</div></div>

  <div class="section-title" style="margin-top: 24px;">Recent alerts</div>
  <div id="alert-list"><div class="loading">Loading...</div></div>
</div>

<div id="status-bar">Connecting to Phalanx...</div>

<script>
async function refresh() {
  try {
    const res = await fetch('/api/dashboard');
    if (!res.ok) throw new Error('API ' + res.status);
    const d = await res.json();

    // Cards
    document.getElementById('devices-count').textContent =
      d.devices.online + ' / ' + d.devices.total;
    document.getElementById('devices-sub').textContent =
      d.devices.online === d.devices.total ? 'All systems normal' : 'Some devices offline';

    document.getElementById('blocked-count').textContent =
      d.blocklist.total_domains.toLocaleString();
    document.getElementById('blocked-sub').textContent = 'In active blocklist';

    const dns = d.dns || {};
    document.getElementById('dns-count').textContent =
      (dns.queries || 0).toLocaleString();
    document.getElementById('dns-sub').textContent =
      (dns.blocked || 0) + ' blocked, ' + (dns.cached || 0) + ' cached';

    // Devices
    const dl = document.getElementById('device-list');
    if (d.devices.list && d.devices.list.length > 0) {
      dl.innerHTML = d.devices.list.map(dev => {
        const online = (Date.now()/1000 - dev.last_seen) < 300;
        return '<div class="device">' +
          '<div><div class="device-name">' + esc(dev.name) + '</div>' +
          '<div class="device-meta">' + esc(dev.ip) + ' · ' + esc(dev.device_type) + '</div></div>' +
          '<div class="dot ' + (online ? 'dot-green' : 'dot-gray') + '"></div></div>';
      }).join('');
    } else {
      dl.innerHTML = '<div class="loading">No devices seen yet. Point your router DNS to this Pi.</div>';
    }

    // Alerts
    const al = document.getElementById('alert-list');
    const alerts = d.alerts.recent || [];
    if (alerts.length > 0) {
      al.innerHTML = alerts.map(a =>
        '<div class="alert alert-' + a.severity + '">' +
        '<span class="alert-sev">' + a.severity.toUpperCase() + '</span> ' +
        '<strong>' + esc(a.device_name || a.device_ip) + '</strong>' +
        '<div class="alert-msg">' + esc(a.message) + '</div></div>'
      ).join('');
    } else {
      al.innerHTML = '<div class="loading">No alerts. Your network looks clean.</div>';
    }

    // Subscription status
    const sub = d.subscription || {};
    let statusText = 'Phalanx running';
    if (sub.status === 'active') statusText += ' · Subscription active';
    else if (sub.status === 'grace') statusText += ' · Subscription expiring in ' + sub.days_until_freeze + ' days';
    else if (sub.status === 'lapsed') statusText += ' · Blocklists frozen (subscription expired)';
    else statusText += ' · Free mode (no subscription)';
    statusText += ' · ' + d.blocklist.total_domains.toLocaleString() + ' domains blocked';
    document.getElementById('status-bar').textContent = statusText;

  } catch (e) {
    document.getElementById('status-bar').textContent = 'Error: ' + e.message;
  }
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""
