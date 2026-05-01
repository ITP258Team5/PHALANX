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
from core.database import get_connection

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


def _is_same_origin(origin: str, host: str) -> bool:
    """Check if an Origin header matches the Host header."""
    # Origin is like "http://192.168.1.50" or "http://192.168.1.50:80"
    # Host is like "192.168.1.50" or "192.168.1.50:80"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        origin_host = parsed.hostname or ""
        origin_port = parsed.port

        host_parts = host.split(":")
        req_host = host_parts[0]
        req_port = int(host_parts[1]) if len(host_parts) > 1 else (443 if parsed.scheme == "https" else 80)

        if origin_port is None:
            origin_port = 443 if parsed.scheme == "https" else 80

        return origin_host == req_host and origin_port == req_port
    except Exception:
        return False

# CSRF protection header — must be present on all state-changing requests.
# HTML forms cannot set custom headers, so cross-origin form submissions fail.
# Cross-origin fetch() with custom headers triggers a CORS preflight, which
# we reject by not sending Access-Control-Allow-Origin for foreign origins.
CSRF_HEADER = "X-Phalanx-Request"


def create_app(subscription_mgr, blocklist_mgr, traffic_monitor) -> web.Application:
    app = web.Application()
    app["sub"] = subscription_mgr
    app["blocklist"] = blocklist_mgr
    app["monitor"] = traffic_monitor

    # ── CORS + CSRF middleware ──
    @web.middleware
    async def csrf_middleware(request: web.Request, handler):
        # Allow non-API routes (static files, GUI)
        if not request.path.startswith("/api/"):
            return await handler(request)

        # GET/HEAD/OPTIONS are safe — no CSRF check needed
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await handler(request)
            # Add CORS headers for same-origin only
            origin = request.headers.get("Origin", "")
            host = request.headers.get("Host", "")
            if origin and _is_same_origin(origin, host):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Headers"] = f"Content-Type, Authorization, {CSRF_HEADER}"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
            return response

        # POST/PUT/DELETE: require the CSRF header
        if not request.headers.get(CSRF_HEADER):
            logger.warning("CSRF: Missing %s header from %s on %s",
                           CSRF_HEADER, request.remote, request.path)
            return web.json_response(
                {"error": "Request rejected — missing security header"},
                status=403,
            )

        # Check Origin header if present (defense in depth)
        origin = request.headers.get("Origin", "")
        host = request.headers.get("Host", "")
        if origin and not _is_same_origin(origin, host):
            logger.warning("CSRF: Origin mismatch — origin=%s host=%s path=%s",
                           origin, host, request.path)
            return web.json_response(
                {"error": "Cross-origin request rejected"},
                status=403,
            )

        response = await handler(request)
        return response

    # ── Auth middleware ──
    @web.middleware
    async def auth_middleware(request: web.Request, handler):
        # Always allow auth endpoints and static files
        if request.path.startswith("/api/auth") or not request.path.startswith("/api/"):
            return await handler(request)

        sub = request.app["sub"]

        # Setup mode: no user has ever configured the device.
        if sub.user_id is None and not sub.is_authenticated:
            return await handler(request)

        # Normal mode: require auth
        if not sub.is_authenticated:
            return web.json_response(
                {"error": "Session expired. Please sign in again."},
                status=401,
            )

        return await handler(request)

    app.middlewares.append(csrf_middleware)
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
        dns_proto = request.app.get("dns_protocol")

        # Get DB devices
        db_devices = monitor.get_device_summary()
        db_ips = {d["ip"] for d in db_devices}

        # Merge in-memory clients that haven't been flushed to DB yet
        if dns_proto:
            now = time.time()
            for ip, last_seen in dns_proto._client_last_seen.items():
                if ip not in db_ips:
                    db_devices.append({
                        "ip": ip,
                        "mac": "",
                        "name": ip,
                        "device_type": "unknown",
                        "first_seen": last_seen,
                        "last_seen": last_seen,
                        "is_blocked": False,
                    })
                else:
                    # Update last_seen from memory if more recent than DB
                    for d in db_devices:
                        if d["ip"] == ip and last_seen > d.get("last_seen", 0):
                            d["last_seen"] = last_seen

        devices = db_devices
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
        """Device list also merges in-memory clients."""
        dns_proto = request.app.get("dns_protocol")
        devices = request.app["monitor"].get_device_summary()
        db_ips = {d["ip"] for d in devices}

        if dns_proto:
            for ip, last_seen in dns_proto._client_last_seen.items():
                if ip not in db_ips:
                    devices.append({
                        "ip": ip, "mac": "", "name": ip,
                        "device_type": "unknown", "first_seen": last_seen,
                        "last_seen": last_seen, "is_blocked": False,
                    })

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
            sys_mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            system_info = {
                "memory_rss_mb": round(mem.rss / 1024 / 1024, 1),
                "memory_vms_mb": round(mem.vms / 1024 / 1024, 1),
                "system_memory_total_mb": round(sys_mem.total / 1024 / 1024, 1),
                "system_memory_used_pct": sys_mem.percent,
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "cpu_count": psutil.cpu_count(),
                "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
                "disk_used_pct": disk.percent,
                "uptime_seconds": round(time.time() - proc.create_time()),
            }
        except ImportError:
            system_info = {"note": "psutil not installed"}

        # Pi CPU temperature
        try:
            temp_str = Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()
            system_info["cpu_temp_c"] = round(int(temp_str) / 1000, 1)
        except Exception:
            system_info["cpu_temp_c"] = None

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

    # ── Live feed (recent blocked/allowed from in-memory ring buffer) ──

    async def blocked_recent(request: web.Request):
        dns_proto = request.app.get("dns_protocol")
        if not dns_proto:
            return web.json_response({"blocked": [], "allowed": []})
        return web.json_response({
            "blocked": list(reversed(dns_proto._recent_blocked)),
            "allowed": list(reversed(dns_proto._recent_allowed)),
        })

    # ── Advanced reporting (full query log + aggregations) ──

    async def report_full(request: web.Request):
        """
        Full advanced reporting data for the advanced panel.
        Returns query log, top blocked/allowed domains, per-client stats,
        query type distribution, and hourly activity breakdown.
        """
        dns_proto = request.app.get("dns_protocol")
        if not dns_proto:
            return web.json_response({"query_log": [], "top_blocked": [], "clients": []})

        # Top blocked domains (sorted by count, top 25)
        top_blocked = sorted(
            dns_proto._domain_block_counts.items(),
            key=lambda x: x[1], reverse=True
        )[:25]

        # Top allowed domains (top 25)
        top_allowed = sorted(
            dns_proto._domain_allow_counts.items(),
            key=lambda x: x[1], reverse=True
        )[:25]

        # Per-client breakdown
        clients = []
        for ip, total in sorted(
            dns_proto._client_query_counts.items(),
            key=lambda x: x[1], reverse=True
        ):
            blocked = dns_proto._client_block_counts.get(ip, 0)
            clients.append({
                "ip": ip,
                "total_queries": total,
                "blocked_queries": blocked,
                "block_rate": round(100.0 * blocked / total, 1) if total > 0 else 0,
            })

        # Query type distribution
        qtypes = [
            {"type": qtype, "count": count}
            for qtype, count in sorted(
                dns_proto._qtype_counts.items(),
                key=lambda x: x[1], reverse=True
            )
        ]

        # Hourly activity (24 buckets)
        hourly = []
        for h in range(24):
            hourly.append({
                "hour": h,
                "total": dns_proto._hourly_total.get(h, 0),
                "blocked": dns_proto._hourly_blocks.get(h, 0),
            })

        # Full query log (most recent first)
        query_log = list(reversed(dns_proto._query_log))

        return web.json_response({
            "query_log": query_log,
            "top_blocked": [{"domain": d, "count": c} for d, c in top_blocked],
            "top_allowed": [{"domain": d, "count": c} for d, c in top_allowed],
            "clients": clients,
            "query_types": qtypes,
            "hourly": hourly,
            "total_queries": dns_proto._stats.get("queries", 0),
            "total_blocked": dns_proto._stats.get("blocked", 0),
            "total_cached": dns_proto._stats.get("cached", 0),
            "total_forwarded": dns_proto._stats.get("forwarded", 0),
        })

    app.router.add_get("/api/live", blocked_recent)
    app.router.add_get("/api/report", report_full)

    # ── GeoIP threat intelligence ──

    async def geoip_lookup(request: web.Request):
        """Look up GeoIP info for blocked domains. Shows where threats originate."""
        from core.net_tools import geoip

        dns_proto = request.app.get("dns_protocol")
        if not dns_proto:
            return web.json_response({"threats": [], "cached": 0})

        # Get top blocked domains and look up their locations
        top_blocked = sorted(
            dns_proto._domain_block_counts.items(),
            key=lambda x: x[1], reverse=True
        )[:15]

        domains = [d for d, _ in top_blocked]
        threats = await geoip.bulk_lookup(domains, max_lookups=15)

        # Add block counts to results
        for t in threats:
            t["block_count"] = dns_proto._domain_block_counts.get(t.get("domain", ""), 0)

        # Country summary
        countries = {}
        for t in threats:
            cc = t.get("countryCode", "??")
            name = t.get("country", "Unknown")
            countries[cc] = countries.get(cc, {"code": cc, "name": name, "count": 0, "domains": []})
            countries[cc]["count"] += t.get("block_count", 1)
            countries[cc]["domains"].append(t.get("domain", ""))

        return web.json_response({
            "threats": threats,
            "countries": sorted(countries.values(), key=lambda x: x["count"], reverse=True),
            "cached": geoip.cache_size,
        })

    # ── Network device discovery ──

    async def network_scan(request: web.Request):
        """Discover devices on the local network using nmap or ARP."""
        from core.net_tools import scanner

        force = request.query.get("force", "false") == "true"
        devices = await scanner.scan(force=force)

        return web.json_response({
            "devices": devices,
            "count": len(devices),
            "scan_age_seconds": round(scanner.last_scan_age, 1),
            "method": "nmap" if any(d.get("vendor") for d in devices) else "arp",
        })

    app.router.add_get("/api/geoip", geoip_lookup)
    app.router.add_get("/api/network/scan", network_scan)

    # ── Honeypot ──

    async def honeypot_stats(request: web.Request):
        """Full honeypot stats: sessions, events, credentials, per-service."""
        from core.honeypot import get_honeypot_stats
        return web.json_response(get_honeypot_stats())

    async def honeypot_session_detail(request: web.Request):
        """Get events for a specific honeypot session."""
        from core.honeypot import get_honeypot_stats
        try:
            session_id = int(request.match_info["session_id"])
        except (ValueError, KeyError):
            return web.json_response({"error": "Invalid session ID"}, status=400)
        conn = get_connection()
        events = conn.execute(
            """SELECT * FROM honeypot_log WHERE session_id = ? ORDER BY timestamp""",
            (session_id,),
        ).fetchall()
        return web.json_response({"session_id": session_id, "events": [dict(r) for r in events]})

    app.router.add_get("/api/honeypot", honeypot_stats)
    app.router.add_get("/api/honeypot/session/{session_id}", honeypot_session_detail)

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
  .header { padding: 16px 24px; background: #161822; border-bottom: 1px solid #2a2d3a; display: flex; align-items: center; gap: 14px; }
  .logo { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #3b82f6, #06b6d4); display: flex; align-items: center; justify-content: center; font-weight: 700; color: #fff; font-size: 18px; }
  .title { font-size: 17px; font-weight: 700; }
  .subtitle { font-size: 11px; color: #6b7280; }
  .container { max-width: 860px; margin: 0 auto; padding: 20px 24px; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  .card { background: #181b25; border-radius: 12px; padding: 16px; border: 1px solid #2a2d3a; }
  .card-label { font-size: 10px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.7px; }
  .card-value { font-size: 24px; font-weight: 700; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }
  .card-sub { font-size: 11px; color: #6b7280; margin-top: 2px; }
  .section { margin-bottom: 20px; }
  .section-title { font-size: 13px; font-weight: 600; color: #9ca3af; margin-bottom: 10px; }
  .row { display: flex; gap: 12px; margin-bottom: 20px; }
  .col { flex: 1; }
  .panel { background: #181b25; border-radius: 12px; padding: 16px; border: 1px solid #2a2d3a; }
  .input-row { display: flex; gap: 8px; margin-top: 8px; }
  input[type=text] { flex: 1; padding: 8px 12px; background: #0f1117; border: 1px solid #2a2d3a; border-radius: 8px; color: #e2e4e9; font-size: 13px; font-family: inherit; outline: none; }
  .btn { padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; font-family: inherit; }
  .btn-blue { background: rgba(59,130,253,0.15); color: #3b82f6; }
  .btn-red { background: rgba(240,82,82,0.12); color: #f05252; }
  .btn-green { background: rgba(45,212,160,0.12); color: #2dd4a0; }
  .btn-gray { background: rgba(124,130,152,0.12); color: #9ca3af; }
  .toggle { display: flex; align-items: center; gap: 10px; margin-left: auto; }
  .toggle-dot { width: 10px; height: 10px; border-radius: 50%; }
  .device { background: #181b25; border: 1px solid #2a2d3a; border-radius: 10px; padding: 12px 16px; margin-bottom: 6px; display: flex; align-items: center; gap: 12px; }
  .device-name { font-size: 13px; font-weight: 600; }
  .device-meta { font-size: 11px; color: #6b7280; margin-top: 1px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; margin-left: auto; }
  .dot-green { background: #22c55e; box-shadow: 0 0 6px #22c55e66; }
  .dot-gray { background: #6b7280; }
  .feed { max-height: 260px; overflow-y: auto; }
  .feed-item { padding: 6px 0; border-bottom: 1px solid #1e2030; font-size: 12px; display: flex; gap: 10px; align-items: center; font-family: 'JetBrains Mono', monospace; }
  .feed-domain { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .feed-blocked { color: #f05252; }
  .feed-allowed { color: #6b7280; }
  .feed-client { color: #4e5470; font-size: 11px; min-width: 100px; text-align: right; }
  .feed-time { color: #4e5470; font-size: 10px; min-width: 50px; text-align: right; }
  .msg { font-size: 12px; padding: 6px 0; }
  .msg-ok { color: #2dd4a0; }
  .msg-err { color: #f05252; }
  #status-bar { padding: 6px 24px; font-size: 11px; color: #6b7280; background: #161822; border-top: 1px solid #2a2d3a; position: fixed; bottom: 0; width: 100%; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">P</div>
  <div><div class="title">Project Phalanx</div><div class="subtitle">Home Network Guardian</div></div>
  <div class="toggle">
    <span id="engine-label" style="font-size:12px;color:#6b7280;">Blocking:</span>
    <div id="engine-dot" class="toggle-dot" style="background:#22c55e;"></div>
    <button class="btn btn-gray" id="engine-btn" onclick="toggleEngine()">Pause</button>
  </div>
</div>

<div class="container">
  <div class="cards">
    <div class="card">
      <div class="card-label">Devices</div>
      <div class="card-value" id="c-devices" style="color:#22c55e;">—</div>
      <div class="card-sub" id="c-devices-sub">loading</div>
    </div>
    <div class="card">
      <div class="card-label">Blocklist</div>
      <div class="card-value" id="c-blocked" style="color:#3b82f6;">—</div>
      <div class="card-sub">domains loaded</div>
    </div>
    <div class="card">
      <div class="card-label">Queries</div>
      <div class="card-value" id="c-queries" style="color:#a78bfa;">—</div>
      <div class="card-sub" id="c-queries-sub">loading</div>
    </div>
    <div class="card">
      <div class="card-label">Blocked</div>
      <div class="card-value" id="c-blk" style="color:#f05252;">—</div>
      <div class="card-sub" id="c-blk-sub">threats stopped</div>
    </div>
  </div>

  <div class="row">
    <div class="col panel">
      <div class="section-title">Block a domain</div>
      <div style="font-size:11px;color:#6b7280;">Add a domain to the blocklist. Takes effect immediately.</div>
      <div class="input-row">
        <input type="text" id="bl-input" placeholder="e.g. ads.example.com" onkeydown="if(event.key==='Enter')addBlock()">
        <button class="btn btn-red" onclick="addBlock()">Block</button>
      </div>
      <div id="bl-msg" class="msg"></div>
    </div>
    <div class="col panel">
      <div class="section-title">Allow a domain</div>
      <div style="font-size:11px;color:#6b7280;">Remove a domain from the blocklist (whitelist).</div>
      <div class="input-row">
        <input type="text" id="wl-input" placeholder="e.g. safe-site.com" onkeydown="if(event.key==='Enter')addAllow()">
        <button class="btn btn-green" onclick="addAllow()">Allow</button>
      </div>
      <div id="wl-msg" class="msg"></div>
    </div>
  </div>

  <div class="row">
    <div class="col section">
      <div class="section-title">Live blocked queries</div>
      <div class="panel feed" id="blocked-feed"><div style="color:#6b7280;font-size:12px;padding:8px;">Waiting for data...</div></div>
    </div>
    <div class="col section">
      <div class="section-title">Live allowed queries</div>
      <div class="panel feed" id="allowed-feed"><div style="color:#6b7280;font-size:12px;padding:8px;">Waiting for data...</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Connected devices</div>
    <div id="device-list"><div style="color:#6b7280;font-size:12px;">Loading...</div></div>
  </div>

  <!-- Advanced Reporting -->
  <div style="margin-top:20px;border-top:1px solid #2a2d3a;padding-top:16px;">
    <button class="btn btn-gray" id="report-btn" onclick="toggleReport()" style="width:100%;text-align:left;padding:12px 18px;border:1px solid #2a2d3a;border-radius:10px;display:flex;align-items:center;gap:8px;">
      <span style="font-size:15px;">&#128202;</span>
      <span style="font-weight:600;">Advanced Reporting</span>
      <span id="report-arrow" style="margin-left:auto;font-size:11px;transition:transform 0.2s;">&#9660;</span>
    </button>

    <div id="report-panel" style="display:none;margin-top:14px;">
      <!-- Summary stats bar -->
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;">
        <div class="panel" style="padding:12px;"><div class="card-label">Block rate</div><div id="r-block-rate" class="card-value" style="font-size:20px;color:#f05252;">—</div></div>
        <div class="panel" style="padding:12px;"><div class="card-label">Avg latency</div><div id="r-latency" class="card-value" style="font-size:20px;color:#a78bfa;">—</div></div>
        <div class="panel" style="padding:12px;"><div class="card-label">Unique domains</div><div id="r-unique" class="card-value" style="font-size:20px;color:#3b82f6;">—</div></div>
        <div class="panel" style="padding:12px;"><div class="card-label">Active clients</div><div id="r-clients" class="card-value" style="font-size:20px;color:#22c55e;">—</div></div>
      </div>

      <!-- Top blocked + query types row -->
      <div class="row">
        <div class="col panel">
          <div class="section-title" style="margin-bottom:8px;">Top blocked domains</div>
          <div id="r-top-blocked" style="max-height:200px;overflow-y:auto;font-size:12px;font-family:'JetBrains Mono',monospace;"></div>
        </div>
        <div class="col panel">
          <div class="section-title" style="margin-bottom:8px;">Query type distribution</div>
          <div id="r-qtypes" style="max-height:200px;overflow-y:auto;font-size:12px;"></div>
        </div>
      </div>

      <!-- Per-client breakdown -->
      <div class="panel" style="margin-bottom:16px;">
        <div class="section-title" style="margin-bottom:8px;">Per-device breakdown</div>
        <div style="font-size:11px;color:#4e5470;margin-bottom:8px;">Queries, blocks, and block rate per connected device</div>
        <div id="r-clients-table"></div>
      </div>

      <!-- Hourly activity -->
      <div class="panel" style="margin-bottom:16px;">
        <div class="section-title" style="margin-bottom:8px;">Hourly activity</div>
        <div id="r-hourly" style="display:flex;align-items:flex-end;gap:2px;height:80px;padding-top:8px;"></div>
        <div style="display:flex;justify-content:space-between;font-size:9px;color:#4e5470;margin-top:4px;">
          <span>12am</span><span>6am</span><span>12pm</span><span>6pm</span><span>11pm</span>
        </div>
      </div>

      <!-- Full query log -->
      <div class="panel">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div class="section-title" style="margin:0;">Query log</div>
          <div style="display:flex;gap:4px;">
            <button class="btn btn-gray" style="font-size:11px;padding:3px 10px;" onclick="setLogFilter('all')">All</button>
            <button class="btn btn-red" style="font-size:11px;padding:3px 10px;" onclick="setLogFilter('blocked')">Blocked</button>
            <button class="btn btn-green" style="font-size:11px;padding:3px 10px;" onclick="setLogFilter('allowed')">Allowed</button>
          </div>
        </div>
        <div id="r-query-log" style="max-height:300px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:11px;"></div>
      </div>

      <!-- Threat Intelligence -->
      <div class="panel" style="margin-top:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div class="section-title" style="margin:0;">Threat intelligence</div>
          <button class="btn btn-blue" style="font-size:11px;padding:3px 10px;" onclick="fetchGeoIP()">Scan origins</button>
        </div>
        <div style="font-size:11px;color:#4e5470;margin-bottom:10px;">Geographic origin of blocked domains — shows where trackers and ads are hosted</div>
        <div id="r-geoip-countries" style="margin-bottom:12px;"></div>
        <div id="r-geoip-table" style="max-height:220px;overflow-y:auto;font-size:11px;"></div>
      </div>

      <!-- Network Device Discovery -->
      <div class="panel" style="margin-top:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div class="section-title" style="margin:0;">Network device discovery</div>
          <button class="btn btn-blue" style="font-size:11px;padding:3px 10px;" onclick="fetchNetScan()">Scan network</button>
        </div>
        <div style="font-size:11px;color:#4e5470;margin-bottom:10px;">All devices detected on your local network — IP, MAC address, vendor, and hostname</div>
        <div id="r-net-scan"></div>
      </div>

      <!-- System Health -->
      <div class="panel" style="margin-top:16px;">
        <div class="section-title" style="margin-bottom:10px;">System health</div>
        <div id="r-sys-health"></div>
      </div>

      <!-- Honeypot -->
      <div class="panel" style="margin-top:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div class="section-title" style="margin:0;">Honeypot</div>
          <button class="btn btn-blue" style="font-size:11px;padding:3px 10px;" onclick="fetchHoneypot()">Refresh</button>
        </div>
        <div style="font-size:11px;color:#4e5470;margin-bottom:12px;">Fake services trapping attackers — SSH(:22), Telnet(:23), HTTP(:8888), FTP(:21). Real SSH is on port 2222.</div>

        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;">
          <div style="background:#0f1117;border-radius:8px;padding:10px;">
            <div class="card-label">Sessions</div>
            <div id="hp-sessions" style="font-size:18px;font-weight:700;color:#a78bfa;margin-top:2px;">0</div>
          </div>
          <div style="background:#0f1117;border-radius:8px;padding:10px;">
            <div class="card-label">Attackers</div>
            <div id="hp-attackers" style="font-size:18px;font-weight:700;color:#f5a623;margin-top:2px;">0</div>
          </div>
          <div style="background:#0f1117;border-radius:8px;padding:10px;">
            <div class="card-label">Auth attempts</div>
            <div id="hp-auth" style="font-size:18px;font-weight:700;color:#f05252;margin-top:2px;">0</div>
          </div>
          <div style="background:#0f1117;border-radius:8px;padding:10px;">
            <div class="card-label">High severity</div>
            <div id="hp-critical" style="font-size:18px;font-weight:700;color:#f05252;margin-top:2px;">0</div>
          </div>
        </div>

        <div class="row">
          <div class="col">
            <div style="font-size:12px;font-weight:600;color:#9ca3af;margin-bottom:6px;">Recent sessions</div>
            <div id="hp-session-list" style="max-height:200px;overflow-y:auto;font-size:11px;"></div>
          </div>
          <div class="col">
            <div style="font-size:12px;font-weight:600;color:#9ca3af;margin-bottom:6px;">Top captured credentials</div>
            <div id="hp-creds" style="max-height:200px;overflow-y:auto;font-size:11px;font-family:'JetBrains Mono',monospace;"></div>
          </div>
        </div>

        <div style="margin-top:12px;">
          <div style="font-size:12px;font-weight:600;color:#9ca3af;margin-bottom:6px;">Event log</div>
          <div id="hp-events" style="max-height:220px;overflow-y:auto;font-size:11px;font-family:'JetBrains Mono',monospace;"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="status-bar">Connecting to Phalanx...</div>

<script>
const H = {'Content-Type':'application/json','X-Phalanx-Request':'1'};

function esc(s) { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }

function ago(ts) {
  const s=Math.floor(Date.now()/1000-ts);
  if(s<5) return 'now';
  if(s<60) return s+'s';
  if(s<3600) return Math.floor(s/60)+'m';
  return Math.floor(s/3600)+'h';
}

async function refresh() {
  try {
    const [dash, live] = await Promise.all([
      fetch('/api/dashboard').then(r=>r.json()),
      fetch('/api/live').then(r=>r.json()),
    ]);

    document.getElementById('c-devices').textContent = dash.devices.online+'/'+dash.devices.total;
    document.getElementById('c-devices-sub').textContent = dash.devices.online===dash.devices.total?'all online':((dash.devices.total-dash.devices.online)+' offline');
    document.getElementById('c-blocked').textContent = (dash.blocklist.total_domains||0).toLocaleString();
    const dns=dash.dns||{};
    document.getElementById('c-queries').textContent = (dns.queries||0).toLocaleString();
    document.getElementById('c-queries-sub').textContent = (dns.cached||0)+' cached, '+(dns.forwarded||0)+' forwarded';
    document.getElementById('c-blk').textContent = (dns.blocked||0).toLocaleString();

    const eng = dns.blocking_enabled!==false;
    document.getElementById('engine-dot').style.background = eng?'#22c55e':'#f05252';
    document.getElementById('engine-label').textContent = eng?'Blocking: ON':'Blocking: OFF';
    document.getElementById('engine-btn').textContent = eng?'Pause':'Resume';

    // Devices
    const dl=document.getElementById('device-list');
    if(dash.devices.list&&dash.devices.list.length>0){
      dl.innerHTML=dash.devices.list.map(d=>{
        const on=(Date.now()/1000-d.last_seen)<300;
        return '<div class="device"><div><div class="device-name">'+esc(d.name)+'</div><div class="device-meta">'+esc(d.ip)+' · '+esc(d.device_type)+'</div></div><div class="dot '+(on?'dot-green':'dot-gray')+'"></div></div>';
      }).join('');
    } else {
      dl.innerHTML='<div style="color:#6b7280;font-size:12px;">No devices seen yet. Point a device DNS to this Pi.</div>';
    }

    // Live feeds
    renderFeed('blocked-feed', live.blocked||[], true);
    renderFeed('allowed-feed', live.allowed||[], false);

    // Status bar
    const sub=dash.subscription||{};
    let st='Phalanx running';
    if(sub.status==='active') st+=' · Subscription active';
    else if(sub.status==='lapsed') st+=' · Blocklists frozen';
    else st+=' · Free mode';
    document.getElementById('status-bar').textContent=st;

  } catch(e) {
    document.getElementById('status-bar').textContent='Error: '+e.message;
  }
}

function renderFeed(id, items, isBlocked) {
  const el=document.getElementById(id);
  if(!items.length) { el.innerHTML='<div style="color:#6b7280;font-size:12px;padding:8px;">None yet</div>'; return; }
  el.innerHTML=items.slice(0,25).map(i=>
    '<div class="feed-item"><span class="feed-domain '+(isBlocked?'feed-blocked':'feed-allowed')+'">'+esc(i.domain)+'</span><span class="feed-client">'+esc(i.client)+'</span><span class="feed-time">'+ago(i.time)+'</span></div>'
  ).join('');
}

async function addBlock() {
  const inp=document.getElementById('bl-input');
  const domain=inp.value.trim();
  if(!domain) return;
  try {
    const r=await fetch('/api/blocklist/blacklist',{method:'POST',headers:H,body:JSON.stringify({domain})});
    const d=await r.json();
    document.getElementById('bl-msg').innerHTML=r.ok?'<span class="msg-ok">Blocked '+esc(domain)+'</span>':'<span class="msg-err">'+esc(d.error||'Failed')+'</span>';
    inp.value='';
    setTimeout(()=>document.getElementById('bl-msg').innerHTML='',4000);
  } catch(e) { document.getElementById('bl-msg').innerHTML='<span class="msg-err">Error</span>'; }
}

async function addAllow() {
  const inp=document.getElementById('wl-input');
  const domain=inp.value.trim();
  if(!domain) return;
  try {
    const r=await fetch('/api/blocklist/whitelist',{method:'POST',headers:H,body:JSON.stringify({domain})});
    const d=await r.json();
    document.getElementById('wl-msg').innerHTML=r.ok?'<span class="msg-ok">Allowed '+esc(domain)+'</span>':'<span class="msg-err">'+esc(d.error||'Failed')+'</span>';
    inp.value='';
    setTimeout(()=>document.getElementById('wl-msg').innerHTML='',4000);
  } catch(e) { document.getElementById('wl-msg').innerHTML='<span class="msg-err">Error</span>'; }
}

async function toggleEngine() {
  try {
    const st=await fetch('/api/engine').then(r=>r.json());
    const r=await fetch('/api/engine/toggle',{method:'POST',headers:H,body:JSON.stringify({enabled:!st.blocking_enabled})});
    refresh();
  } catch(e) {}
}

refresh();
setInterval(refresh, 3000);

// ── Advanced Reporting ──
let reportOpen = false;
let reportData = null;
let logFilter = 'all';

function toggleReport() {
  reportOpen = !reportOpen;
  document.getElementById('report-panel').style.display = reportOpen ? 'block' : 'none';
  document.getElementById('report-arrow').style.transform = reportOpen ? 'rotate(180deg)' : 'none';
  if (reportOpen) { fetchReport(); fetchHealth(); fetchHoneypot(); }
}

function setLogFilter(f) { logFilter = f; if (reportData) renderQueryLog(reportData.query_log); }

async function fetchReport() {
  try {
    const r = await fetch('/api/report');
    reportData = await r.json();
    renderReport(reportData);
  } catch(e) {}
}

function renderReport(d) {
  // Block rate
  const rate = d.total_queries > 0 ? (100*d.total_blocked/d.total_queries).toFixed(1) : '0';
  document.getElementById('r-block-rate').textContent = rate + '%';

  // Avg latency
  const logs = d.query_log || [];
  if (logs.length > 0) {
    const avg = logs.reduce((a,l) => a + (l.latency_ms||0), 0) / logs.length;
    document.getElementById('r-latency').textContent = avg.toFixed(1) + 'ms';
  }

  // Unique domains
  const unique = new Set([...d.top_blocked.map(x=>x.domain), ...d.top_allowed.map(x=>x.domain)]);
  document.getElementById('r-unique').textContent = unique.size.toString();

  // Active clients
  document.getElementById('r-clients').textContent = (d.clients||[]).length.toString();

  // Top blocked domains
  const tb = document.getElementById('r-top-blocked');
  if (d.top_blocked.length > 0) {
    const maxC = d.top_blocked[0].count;
    tb.innerHTML = d.top_blocked.slice(0,15).map(x => {
      const pct = Math.max(5, 100*x.count/maxC);
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">'+
        '<div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#f05252;">'+esc(x.domain)+'</div>'+
        '<div style="width:120px;height:12px;background:#1e2030;border-radius:3px;overflow:hidden;">'+
        '<div style="width:'+pct+'%;height:100%;background:#f0525244;border-radius:3px;"></div></div>'+
        '<div style="min-width:40px;text-align:right;color:#6b7280;">'+x.count+'</div></div>';
    }).join('');
  } else {
    tb.innerHTML = '<div style="color:#6b7280;">No blocked domains yet</div>';
  }

  // Query types
  const qt = document.getElementById('r-qtypes');
  if (d.query_types.length > 0) {
    const colors = {A:'#3b82f6',AAAA:'#a78bfa',HTTPS:'#22c55e',MX:'#f5a623',CNAME:'#06b6d4',TXT:'#ec4899',SRV:'#f97316',PTR:'#8b5cf6'};
    const total = d.query_types.reduce((a,x)=>a+x.count,0);
    qt.innerHTML = d.query_types.map(x => {
      const pct = (100*x.count/total).toFixed(1);
      const col = colors[x.type] || '#6b7280';
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'+
        '<div style="width:50px;font-weight:600;color:'+col+';">'+esc(x.type)+'</div>'+
        '<div style="flex:1;height:14px;background:#1e2030;border-radius:3px;overflow:hidden;">'+
        '<div style="width:'+pct+'%;height:100%;background:'+col+'33;border-radius:3px;"></div></div>'+
        '<div style="min-width:60px;text-align:right;color:#6b7280;font-size:11px;">'+x.count+' ('+pct+'%)</div></div>';
    }).join('');
  }

  // Per-client table
  const ct = document.getElementById('r-clients-table');
  if (d.clients.length > 0) {
    ct.innerHTML =
      '<div style="display:grid;grid-template-columns:140px 80px 80px 70px;gap:0;font-size:11px;">'+
      '<div style="color:#4e5470;font-weight:600;padding:4px 0;border-bottom:1px solid #252a38;">Device</div>'+
      '<div style="color:#4e5470;font-weight:600;padding:4px 0;border-bottom:1px solid #252a38;text-align:right;">Queries</div>'+
      '<div style="color:#4e5470;font-weight:600;padding:4px 0;border-bottom:1px solid #252a38;text-align:right;">Blocked</div>'+
      '<div style="color:#4e5470;font-weight:600;padding:4px 0;border-bottom:1px solid #252a38;text-align:right;">Rate</div>'+
      d.clients.map(c =>
        '<div style="padding:4px 0;border-bottom:1px solid #1e2030;font-family:\'JetBrains Mono\',monospace;">'+esc(c.ip)+'</div>'+
        '<div style="padding:4px 0;border-bottom:1px solid #1e2030;text-align:right;color:#9ca3af;">'+c.total_queries+'</div>'+
        '<div style="padding:4px 0;border-bottom:1px solid #1e2030;text-align:right;color:#f05252;">'+c.blocked_queries+'</div>'+
        '<div style="padding:4px 0;border-bottom:1px solid #1e2030;text-align:right;color:'+(c.block_rate>50?'#f05252':'#6b7280')+';">'+c.block_rate+'%</div>'
      ).join('')+
      '</div>';
  }

  // Hourly chart
  const hc = document.getElementById('r-hourly');
  const maxH = Math.max(1, ...d.hourly.map(h=>h.total));
  hc.innerHTML = d.hourly.map(h => {
    const totalH = Math.max(2, 70 * h.total / maxH);
    const blockH = h.total > 0 ? Math.max(0, totalH * h.blocked / h.total) : 0;
    const allowH = totalH - blockH;
    return '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;" title="'+h.hour+':00 — '+h.total+' queries, '+h.blocked+' blocked">'+
      '<div style="width:100%;height:'+blockH+'px;background:#f0525266;border-radius:2px 2px 0 0;"></div>'+
      '<div style="width:100%;height:'+allowH+'px;background:#3b82f633;border-radius:0 0 2px 2px;"></div>'+
      '</div>';
  }).join('');

  // Query log
  renderQueryLog(d.query_log);
}

function renderQueryLog(logs) {
  const el = document.getElementById('r-query-log');
  let filtered = logs;
  if (logFilter === 'blocked') filtered = logs.filter(l=>l.blocked);
  if (logFilter === 'allowed') filtered = logs.filter(l=>!l.blocked);

  if (filtered.length === 0) { el.innerHTML = '<div style="color:#6b7280;padding:8px;">No entries</div>'; return; }

  el.innerHTML =
    '<div style="display:grid;grid-template-columns:60px 1fr 40px 70px 90px 55px;gap:0;color:#4e5470;font-size:10px;font-weight:600;padding-bottom:4px;border-bottom:1px solid #252a38;margin-bottom:4px;">'+
    '<div>TIME</div><div>DOMAIN</div><div>TYPE</div><div>STATUS</div><div>CLIENT</div><div>LATENCY</div></div>'+
    filtered.slice(0,100).map(l => {
      const statusColor = l.blocked ? '#f05252' : (l.resolution==='CACHED'?'#a78bfa':'#2dd4a0');
      const status = l.blocked ? 'BLOCKED' : (l.resolution || 'OK');
      return '<div style="display:grid;grid-template-columns:60px 1fr 40px 70px 90px 55px;gap:0;padding:3px 0;border-bottom:1px solid #1e2030;">'+
        '<div style="color:#4e5470;">'+ago(l.time)+'</div>'+
        '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:'+(l.blocked?'#f05252':'#9ca3af')+';">'+esc(l.domain)+'</div>'+
        '<div style="color:#6b7280;">'+esc(l.qtype)+'</div>'+
        '<div style="color:'+statusColor+';font-weight:600;">'+status+'</div>'+
        '<div style="color:#4e5470;">'+esc(l.client)+'</div>'+
        '<div style="color:#6b7280;text-align:right;">'+(l.latency_ms!=null?l.latency_ms.toFixed(1)+'ms':'—')+'</div>'+
        '</div>';
    }).join('');
}

// Auto-refresh report if panel is open
setInterval(function() { if (reportOpen) fetchReport(); }, 5000);

// ── Threat Intelligence (GeoIP) ──
async function fetchGeoIP() {
  document.getElementById('r-geoip-table').innerHTML = '<div style="color:#6b7280;padding:8px;">Scanning origins...</div>';
  try {
    const r = await fetch('/api/geoip');
    const d = await r.json();
    renderGeoIP(d);
  } catch(e) {
    document.getElementById('r-geoip-table').innerHTML = '<div style="color:#f05252;padding:8px;">Lookup failed</div>';
  }
}

function renderGeoIP(d) {
  // Country summary
  const cc = document.getElementById('r-geoip-countries');
  if (d.countries && d.countries.length > 0) {
    const maxC = d.countries[0].count;
    cc.innerHTML = d.countries.map(c => {
      const pct = Math.max(5, 100*c.count/maxC);
      const flag = getFlagEmoji(c.code);
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:12px;">'+
        '<span style="font-size:16px;">'+flag+'</span>'+
        '<span style="width:100px;">'+esc(c.name)+'</span>'+
        '<div style="flex:1;height:14px;background:#1e2030;border-radius:3px;overflow:hidden;">'+
        '<div style="width:'+pct+'%;height:100%;background:#f0525233;border-radius:3px;"></div></div>'+
        '<span style="min-width:50px;text-align:right;color:#6b7280;font-size:11px;">'+c.count+' blocks</span></div>';
    }).join('');
  } else {
    cc.innerHTML = '<div style="color:#6b7280;">No data yet — browse with DNS pointed at Phalanx to generate blocks</div>';
  }

  // Detailed table
  const tbl = document.getElementById('r-geoip-table');
  if (d.threats && d.threats.length > 0) {
    tbl.innerHTML =
      '<div style="display:grid;grid-template-columns:1fr 80px 80px 100px 50px;gap:0;font-size:10px;color:#4e5470;font-weight:600;padding-bottom:4px;border-bottom:1px solid #252a38;margin-bottom:4px;">'+
      '<div>DOMAIN</div><div>COUNTRY</div><div>CITY</div><div>ISP</div><div style="text-align:right">BLOCKS</div></div>'+
      d.threats.map(t =>
        '<div style="display:grid;grid-template-columns:1fr 80px 80px 100px 50px;gap:0;padding:3px 0;border-bottom:1px solid #1e2030;font-family:\'JetBrains Mono\',monospace;font-size:11px;">'+
        '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#f05252;">'+esc(t.domain)+'</div>'+
        '<div style="color:#9ca3af;">'+getFlagEmoji(t.countryCode)+' '+esc(t.countryCode)+'</div>'+
        '<div style="color:#6b7280;">'+esc(t.city||'—')+'</div>'+
        '<div style="color:#6b7280;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+esc(t.isp||'—')+'</div>'+
        '<div style="text-align:right;color:#f05252;">'+(t.block_count||0)+'</div></div>'
      ).join('');
  }
}

function getFlagEmoji(cc) {
  if (!cc || cc.length !== 2 || cc === 'LO' || cc === '??') return '🌐';
  const offset = 0x1F1E6;
  return String.fromCodePoint(cc.charCodeAt(0)-65+offset, cc.charCodeAt(1)-65+offset);
}

// ── Network Device Discovery ──
async function fetchNetScan() {
  document.getElementById('r-net-scan').innerHTML = '<div style="color:#6b7280;padding:8px;">Scanning network...</div>';
  try {
    const r = await fetch('/api/network/scan?force=true');
    const d = await r.json();
    renderNetScan(d);
  } catch(e) {
    document.getElementById('r-net-scan').innerHTML = '<div style="color:#f05252;padding:8px;">Scan failed</div>';
  }
}

function renderNetScan(d) {
  const el = document.getElementById('r-net-scan');
  if (!d.devices || d.devices.length === 0) {
    el.innerHTML = '<div style="color:#6b7280;">No devices found</div>';
    return;
  }
  el.innerHTML =
    '<div style="font-size:10px;color:#4e5470;margin-bottom:6px;">'+d.count+' devices found via '+esc(d.method)+' ('+Math.round(d.scan_age_seconds)+'s ago)</div>'+
    '<div style="display:grid;grid-template-columns:120px 140px 120px 1fr;gap:0;font-size:10px;color:#4e5470;font-weight:600;padding-bottom:4px;border-bottom:1px solid #252a38;margin-bottom:4px;">'+
    '<div>IP</div><div>MAC</div><div>VENDOR</div><div>HOSTNAME</div></div>'+
    d.devices.map(dev =>
      '<div style="display:grid;grid-template-columns:120px 140px 120px 1fr;gap:0;padding:3px 0;border-bottom:1px solid #1e2030;font-family:\'JetBrains Mono\',monospace;font-size:11px;">'+
      '<div style="color:#22c55e;">'+esc(dev.ip)+'</div>'+
      '<div style="color:#6b7280;">'+esc(dev.mac||'—')+'</div>'+
      '<div style="color:#9ca3af;">'+esc(dev.vendor||'—')+'</div>'+
      '<div style="color:#9ca3af;">'+esc(dev.hostname||'—')+'</div></div>'
    ).join('');
}

// ── System Health ──
async function fetchHealth() {
  try {
    const r = await fetch('/api/diagnostics');
    const d = await r.json();
    renderHealth(d);
  } catch(e) {}
}

function renderHealth(d) {
  const s = d.system || {};
  const el = document.getElementById('r-sys-health');

  function bar(label, value, max, unit, color) {
    const pct = Math.min(100, Math.max(0, 100*value/max));
    const warn = pct > 80;
    return '<div style="margin-bottom:10px;">'+
      '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">'+
      '<span style="color:#9ca3af;">'+label+'</span>'+
      '<span style="color:'+(warn?'#f05252':'#6b7280')+';">'+value+unit+'</span></div>'+
      '<div style="height:8px;background:#1e2030;border-radius:4px;overflow:hidden;">'+
      '<div style="width:'+pct+'%;height:100%;background:'+(warn?'#f0525266':color+'66')+';border-radius:4px;"></div></div></div>';
  }

  const upH = Math.floor((s.uptime_seconds||0)/3600);
  const upM = Math.floor(((s.uptime_seconds||0)%3600)/60);

  el.innerHTML =
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">'+
    '<div>'+
    bar('CPU', s.cpu_percent||0, 100, '%', '#a78bfa')+
    bar('Memory', s.system_memory_used_pct||0, 100, '%', '#3b82f6')+
    bar('Disk', s.disk_used_pct||0, 100, '%', '#f5a623')+
    '</div>'+
    '<div>'+
    (s.cpu_temp_c != null ? bar('Temperature', s.cpu_temp_c, 85, '°C', s.cpu_temp_c>70?'#f05252':'#22c55e') : '')+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px;">'+
    '<div class="panel" style="padding:8px;"><div class="card-label">Uptime</div><div style="font-size:14px;font-weight:600;color:#22c55e;margin-top:2px;">'+upH+'h '+upM+'m</div></div>'+
    '<div class="panel" style="padding:8px;"><div class="card-label">Phalanx RSS</div><div style="font-size:14px;font-weight:600;color:#3b82f6;margin-top:2px;">'+(s.memory_rss_mb||0)+' MB</div></div>'+
    '</div></div></div>';
}

// Fetch health when report opens
setInterval(function() { if (reportOpen) fetchHealth(); }, 5000);

// ── Honeypot ──
async function fetchHoneypot() {
  try {
    const r = await fetch('/api/honeypot');
    const d = await r.json();
    renderHoneypot(d);
  } catch(e) {}
}

function renderHoneypot(d) {
  document.getElementById('hp-sessions').textContent = d.total_sessions || 0;
  document.getElementById('hp-attackers').textContent = d.unique_attackers || 0;
  document.getElementById('hp-auth').textContent = d.total_auth_attempts || 0;
  document.getElementById('hp-critical').textContent = d.critical_count || 0;

  // Sessions
  const sl = document.getElementById('hp-session-list');
  if (d.sessions && d.sessions.length > 0) {
    sl.innerHTML = d.sessions.slice(0,15).map(s => {
      const sevC = s.severity==='critical'?'#f05252':s.severity==='high'?'#f5a623':s.severity==='medium'?'#3b82f6':'#6b7280';
      return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #1e2030;">'+
        '<span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:'+sevC+'22;color:'+sevC+';">'+esc(s.severity)+'</span>'+
        '<span style="color:#9ca3af;font-family:\'JetBrains Mono\',monospace;">'+esc(s.attacker_ip)+'</span>'+
        '<span style="color:#6b7280;">→ :'+s.decoy_port+'</span>'+
        '<span style="color:#6b7280;">'+esc(s.service_emulated||'')+'</span>'+
        '<span style="color:#4e5470;margin-left:auto;">'+esc(s.attack_class||'')+'</span>'+
        '</div>';
    }).join('');
  } else {
    sl.innerHTML = '<div style="color:#6b7280;padding:8px;">No sessions yet — honeypot is listening</div>';
  }

  // Credentials
  const cr = document.getElementById('hp-creds');
  if (d.top_credentials && d.top_credentials.length > 0) {
    cr.innerHTML = d.top_credentials.slice(0,10).map(c =>
      '<div style="display:flex;gap:8px;padding:3px 0;border-bottom:1px solid #1e2030;">'+
      '<span style="color:#f5a623;min-width:80px;">'+esc(c.username)+'</span>'+
      '<span style="color:#f05252;">'+esc(c.password_raw)+'</span>'+
      '<span style="color:#4e5470;margin-left:auto;">'+c.attempts+'x</span>'+
      '</div>'
    ).join('');
  } else {
    cr.innerHTML = '<div style="color:#6b7280;padding:8px;">No credentials captured yet</div>';
  }

  // Events
  const ev = document.getElementById('hp-events');
  if (d.events && d.events.length > 0) {
    ev.innerHTML = d.events.slice(0,30).map(e => {
      let detail = '';
      if (e.username) detail = ' user:<span style="color:#f5a623;">'+esc(e.username)+'</span> pass:<span style="color:#f05252;">'+esc(e.password_raw||'')+'</span> → <span style="color:#f05252;">denied</span>';
      if (e.decoded_payload) detail += ' <span style="color:#6b7280;">'+esc(e.decoded_payload.substring(0,60))+'</span>';
      const typeC = e.event_type==='auth_attempt'?'#f05252':e.event_type.includes('open')?'#22c55e':e.event_type.includes('close')?'#6b7280':'#a78bfa';
      return '<div style="padding:3px 0;border-bottom:1px solid #1e2030;">'+
        '<span style="color:#4e5470;">'+ago(e.timestamp)+'</span> '+
        '<span style="color:#9ca3af;">'+esc(e.attacker_ip||'')+'</span> '+
        '<span style="font-weight:600;color:'+typeC+';">'+esc(e.event_type)+'</span>'+
        detail+'</div>';
    }).join('');
  } else {
    ev.innerHTML = '<div style="color:#6b7280;padding:8px;">No events yet</div>';
  }
}

// Auto-refresh honeypot when report panel is open
setInterval(function() { if (reportOpen) fetchHoneypot(); }, 5000);
</script>
</body>
</html>
"""
