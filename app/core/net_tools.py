"""
Phalanx Network Tools

Provides:
  - GeoIP lookup for blocked domains (ip-api.com, free tier)
  - Network device discovery via nmap ping sweep
  - WHOIS domain lookup
  - Reverse DNS resolution

All results are cached in memory to avoid repeated lookups
and to stay within free API rate limits.
"""

import asyncio
import json
import logging
import socket
import subprocess
import re
import time
from typing import Optional

import aiohttp

logger = logging.getLogger("phalanx.tools")


# ── GeoIP Lookup ──

class GeoIPCache:
    """
    Resolves domains to IPs, then looks up geographic location
    via ip-api.com (free, 45 requests/minute).
    """

    def __init__(self, max_cache: int = 500):
        self._cache: dict[str, dict] = {}
        self._max_cache = max_cache
        self._last_request = 0.0
        self._rate_interval = 1.5  # seconds between API calls (safe for free tier)

    async def lookup(self, domain: str) -> Optional[dict]:
        """Look up GeoIP info for a domain. Returns cached if available."""
        domain = domain.lower().strip(".")
        if domain in self._cache:
            return self._cache[domain]

        # Resolve domain to IP first
        try:
            loop = asyncio.get_running_loop()
            result = await loop.getaddrinfo(domain, None)
            if not result:
                return None
            ip = result[0][4][0]
        except (socket.gaierror, OSError):
            return None

        # Skip private/local IPs
        if ip.startswith(("10.", "192.168.", "172.", "127.", "0.")):
            return {"ip": ip, "country": "Local", "countryCode": "LO", "city": "LAN", "isp": "Private"}

        # Rate limit
        now = time.monotonic()
        wait = self._rate_interval - (now - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)

        try:
            self._last_request = time.monotonic()
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                async with session.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as"
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

                    if data.get("status") != "success":
                        return None

                    entry = {
                        "ip": ip,
                        "domain": domain,
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "??"),
                        "region": data.get("region", ""),
                        "city": data.get("city", ""),
                        "lat": data.get("lat", 0),
                        "lon": data.get("lon", 0),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                    }

                    # Cache
                    self._cache[domain] = entry
                    if len(self._cache) > self._max_cache:
                        oldest = next(iter(self._cache))
                        del self._cache[oldest]

                    return entry

        except Exception as e:
            logger.debug("GeoIP lookup failed for %s: %s", domain, e)
            return None

    async def bulk_lookup(self, domains: list[str], max_lookups: int = 15) -> list[dict]:
        """Look up GeoIP for multiple domains. Respects rate limits."""
        results = []
        for domain in domains[:max_lookups]:
            info = await self.lookup(domain)
            if info:
                results.append(info)
        return results

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    @property
    def cached_entries(self) -> list[dict]:
        return list(self._cache.values())


# ── Network Scanner ──

class NetworkScanner:
    """
    Discovers devices on the local network using nmap ping sweep
    or ARP table as fallback.
    """

    def __init__(self):
        self._last_scan: list[dict] = []
        self._last_scan_time: float = 0
        self._scan_cooldown = 60  # seconds between scans

    async def scan(self, subnet: str = None, force: bool = False) -> list[dict]:
        """
        Run a network scan. Returns list of discovered devices.
        Uses nmap if available, falls back to ARP table.
        """
        now = time.time()
        if not force and (now - self._last_scan_time) < self._scan_cooldown:
            return self._last_scan

        if subnet is None:
            subnet = self._detect_subnet()

        # Try nmap first
        devices = await self._scan_nmap(subnet)

        # Fallback to ARP if nmap not available
        if devices is None:
            devices = await self._scan_arp()

        self._last_scan = devices
        self._last_scan_time = now
        return devices

    def _detect_subnet(self) -> str:
        """Detect the local subnet from the Pi's IP."""
        try:
            result = subprocess.run(
                ["hostname", "-I"], capture_output=True, text=True, timeout=5
            )
            ip = result.stdout.strip().split()[0]
            base = ".".join(ip.split(".")[:3])
            return f"{base}.0/24"
        except Exception:
            return "192.168.1.0/24"

    async def _scan_nmap(self, subnet: str) -> Optional[list[dict]]:
        """Run nmap ping sweep (-sn) on the subnet."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sn", "-oX", "-", subnet,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode != 0:
                logger.debug("nmap failed: %s", stderr.decode())
                return None

            return self._parse_nmap_xml(stdout.decode())

        except FileNotFoundError:
            logger.debug("nmap not installed — falling back to ARP")
            return None
        except asyncio.TimeoutError:
            logger.debug("nmap scan timed out")
            return None
        except Exception as e:
            logger.debug("nmap error: %s", e)
            return None

    def _parse_nmap_xml(self, xml_str: str) -> list[dict]:
        """Parse nmap XML output into device list."""
        devices = []
        # Simple regex parsing — avoids requiring xml.etree for security
        host_blocks = re.findall(r"<host\b.*?</host>", xml_str, re.DOTALL)

        for block in host_blocks:
            device = {"ip": "", "mac": "", "vendor": "", "hostname": "", "status": "up"}

            # IP
            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            if ip_match:
                device["ip"] = ip_match.group(1)

            # MAC
            mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"(?:\s+vendor="([^"]*)")?', block)
            if mac_match:
                device["mac"] = mac_match.group(1)
                device["vendor"] = mac_match.group(2) or ""

            # Hostname
            host_match = re.search(r'<hostname name="([^"]+)"', block)
            if host_match:
                device["hostname"] = host_match.group(1)

            if device["ip"]:
                devices.append(device)

        return devices

    async def _scan_arp(self) -> list[dict]:
        """Fallback: read the ARP table for known devices."""
        devices = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            for line in stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    ip = parts[0]
                    mac = parts[4] if len(parts) > 4 else ""
                    state = parts[-1] if parts else "unknown"
                    if state in ("REACHABLE", "STALE", "DELAY"):
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": "",
                            "hostname": "",
                            "status": "up",
                        })

        except Exception as e:
            logger.debug("ARP scan failed: %s", e)

        return devices

    @property
    def last_scan_results(self) -> list[dict]:
        return self._last_scan

    @property
    def last_scan_age(self) -> float:
        if self._last_scan_time == 0:
            return -1
        return time.time() - self._last_scan_time


# ── Singleton instances ──
geoip = GeoIPCache()
scanner = NetworkScanner()
