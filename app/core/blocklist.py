"""
Phalanx Blocklist Manager

Handles downloading, parsing, and storing blocklists. Subscription-gated
lists freeze (keep last known version) when the subscription lapses —
the device never stops working, it just stops updating.

Memory note: The active blocklist is a single Python set. At ~60 bytes
per domain string, 200k domains ≈ 12MB. We keep only one set in memory.
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

import aiohttp

import config

logger = logging.getLogger("phalanx.blocklist")


def parse_hosts_file(content: str) -> set[str]:
    """Parse a hosts-format blocklist (e.g. '0.0.0.0 ad.example.com')."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].lower().strip(".")
            if domain and domain != "localhost":
                domains.add(domain)
    return domains


def parse_domain_list(content: str) -> set[str]:
    """Parse a plain domain-per-line blocklist."""
    domains = set()
    for line in content.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line.strip("."))
    return domains


PARSERS = {
    "hosts": parse_hosts_file,
    "domains": parse_domain_list,
}


class BlocklistManager:
    """
    Manages blocklist lifecycle:
      - Load cached lists from disk on boot
      - Fetch updates (gated by subscription status)
      - Merge all lists into one in-memory set
      - Track staleness for user warnings
    """

    def __init__(
        self,
        blocklist_dir: Path = config.BLOCKLIST_DIR,
        sources: list[dict] = None,
    ):
        self.blocklist_dir = blocklist_dir
        self.blocklist_dir.mkdir(parents=True, exist_ok=True)
        self.sources = sources or config.BLOCKLIST_SOURCES
        self._active_set: set[str] = set()
        self._metadata: dict[str, dict] = {}  # source_name -> {updated_at, count, path}
        self._user_whitelist: set[str] = set()
        self._user_blacklist: set[str] = set()

    @property
    def active_set(self) -> set[str]:
        """The current merged blocklist set (read-only reference)."""
        return self._active_set

    @property
    def domain_count(self) -> int:
        return len(self._active_set)

    @property
    def metadata(self) -> dict:
        return dict(self._metadata)

    def _cache_path(self, source_name: str) -> Path:
        safe_name = source_name.replace(" ", "_").lower()
        return self.blocklist_dir / f"{safe_name}.txt"

    def load_cached(self):
        """Load all cached blocklists from disk (boot-time)."""
        merged = set()
        for source in self.sources:
            path = self._cache_path(source["name"])
            if path.exists():
                content = path.read_text(encoding="utf-8", errors="replace")
                parser = PARSERS.get(source["format"], parse_domain_list)
                domains = parser(content)
                merged.update(domains)
                self._metadata[source["name"]] = {
                    "updated_at": path.stat().st_mtime,
                    "count": len(domains),
                    "path": str(path),
                }
                logger.info(
                    "Loaded cached blocklist '%s': %d domains", source["name"], len(domains)
                )
            else:
                logger.info("No cached blocklist for '%s'", source["name"])

        # Apply user overrides
        merged -= self._user_whitelist
        merged |= self._user_blacklist
        self._active_set = merged
        logger.info("Total active blocklist: %d domains", len(merged))

    async def update(self, subscription_active: bool) -> dict:
        """
        Fetch fresh blocklists from all sources.

        If subscription is lapsed, only free sources update.
        Subscription-required sources keep their cached (frozen) version.

        Returns a summary dict.
        """
        results = {}
        new_domains = set()

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            for source in self.sources:
                name = source["name"]

                if source["subscription_required"] and not subscription_active:
                    # Frozen — use cached version
                    cached_path = self._cache_path(name)
                    if cached_path.exists():
                        content = cached_path.read_text(encoding="utf-8", errors="replace")
                        parser = PARSERS.get(source["format"], parse_domain_list)
                        frozen = parser(content)
                        new_domains.update(frozen)
                        days_old = (time.time() - cached_path.stat().st_mtime) / 86400
                        results[name] = {
                            "status": "frozen",
                            "count": len(frozen),
                            "days_stale": round(days_old, 1),
                        }
                        logger.info("Blocklist '%s' frozen (subscription inactive), %d days old", name, int(days_old))
                    else:
                        results[name] = {"status": "unavailable", "count": 0}
                    continue

                url = source.get("url", "")
                if not url:
                    results[name] = {"status": "no_url", "count": 0}
                    continue

                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            raise Exception(f"HTTP {resp.status}")
                        content = await resp.text()

                    parser = PARSERS.get(source["format"], parse_domain_list)
                    domains = parser(content)

                    # Cache to disk
                    cache_path = self._cache_path(name)
                    cache_path.write_text(content, encoding="utf-8")

                    new_domains.update(domains)
                    self._metadata[name] = {
                        "updated_at": time.time(),
                        "count": len(domains),
                        "path": str(cache_path),
                    }
                    results[name] = {"status": "updated", "count": len(domains)}
                    logger.info("Updated blocklist '%s': %d domains", name, len(domains))

                except Exception as e:
                    logger.error("Failed to update '%s': %s", name, e)
                    # Fall back to cached
                    cached_path = self._cache_path(name)
                    if cached_path.exists():
                        content = cached_path.read_text(encoding="utf-8", errors="replace")
                        parser = PARSERS.get(source["format"], parse_domain_list)
                        fallback = parser(content)
                        new_domains.update(fallback)
                        results[name] = {"status": "fetch_failed_using_cache", "count": len(fallback)}
                    else:
                        results[name] = {"status": "fetch_failed_no_cache", "count": 0}

        # Apply user overrides and swap
        new_domains -= self._user_whitelist
        new_domains |= self._user_blacklist
        self._active_set = new_domains
        logger.info("Blocklist update complete: %d total domains", len(new_domains))
        return results

    def staleness_warning(self) -> Optional[str]:
        """Return a warning message if any subscription list is too stale."""
        for source in self.sources:
            if not source.get("subscription_required"):
                continue
            meta = self._metadata.get(source["name"])
            if meta is None:
                continue
            days_old = (time.time() - meta["updated_at"]) / 86400
            if days_old > config.BLOCKLIST_STALE_THRESHOLD:
                return config.BLOCKLIST_FROZEN_MSG.format(days=int(days_old))
        return None

    def add_whitelist(self, domain: str):
        domain = domain.lower().strip(".")
        self._user_whitelist.add(domain)
        self._active_set.discard(domain)

    def remove_whitelist(self, domain: str):
        domain = domain.lower().strip(".")
        self._user_whitelist.discard(domain)

    def add_blacklist(self, domain: str):
        domain = domain.lower().strip(".")
        self._user_blacklist.add(domain)
        self._active_set.add(domain)

    def remove_blacklist(self, domain: str):
        domain = domain.lower().strip(".")
        self._user_blacklist.discard(domain)
        self._active_set.discard(domain)
