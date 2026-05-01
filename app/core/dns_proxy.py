"""
Phalanx DNS Proxy

Lightweight async DNS proxy that intercepts queries, checks them against
the in-memory blocklist, and either returns a "blocked" response (NXDOMAIN)
or forwards the query to an upstream resolver.

Designed for low memory on a Pi 4. The blocklist is stored as a plain
Python set of domain strings (~60 bytes per entry; 200k domains ≈ 12MB).
"""

import asyncio
import hashlib
import logging
import struct
import time
from collections import OrderedDict
from typing import Optional

import config

logger = logging.getLogger("phalanx.dns")


# ── Minimal DNS helpers (no external dependency) ──

def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from raw packet bytes. Returns (name, new_offset)."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 10
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            # Pointer
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels).lower()
    return name, original_offset if jumped else offset


def extract_query_name(data: bytes) -> Optional[str]:
    """Pull the first QNAME out of a DNS query packet."""
    if len(data) < 12:
        return None
    # Question section starts at byte 12
    try:
        name, _ = parse_dns_name(data, 12)
        return name
    except Exception:
        return None


# DNS record type codes to human-readable names
_QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS",
    255: "ANY",
}


def extract_query_info(data: bytes) -> Optional[dict]:
    """
    Extract query name, type, and class from a DNS packet.
    Returns {"name": str, "qtype": str, "qtype_num": int} or None.
    """
    if len(data) < 12:
        return None
    try:
        name, end_offset = parse_dns_name(data, 12)
        if end_offset + 4 > len(data):
            return {"name": name, "qtype": "?", "qtype_num": 0}
        qtype_num = struct.unpack("!H", data[end_offset:end_offset + 2])[0]
        qtype = _QTYPE_MAP.get(qtype_num, f"TYPE{qtype_num}")
        return {"name": name, "qtype": qtype, "qtype_num": qtype_num}
    except Exception:
        return None


def build_blocked_response(query: bytes) -> bytes:
    """
    Build an NXDOMAIN response for a blocked domain.
    Copies the query ID and question section, sets response flags.
    """
    if len(query) < 12:
        return query

    # Copy transaction ID
    tx_id = query[:2]
    # Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    flags = struct.pack("!H", 0x8583)
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    counts = struct.pack("!HHH", 0, 0, 0)
    # Keep original question section
    qd_count = struct.unpack("!H", query[4:6])[0]
    question_end = 12
    for _ in range(qd_count):
        _, question_end = parse_dns_name(query, question_end)
        question_end += 4  # QTYPE + QCLASS

    return tx_id + flags + query[4:6] + counts + query[12:question_end]


# ── DNS Cache ──

class DNSCache:
    """Simple LRU cache for upstream DNS responses."""

    def __init__(self, max_size: int = config.DNS_CACHE_MAX_SIZE):
        self._cache: OrderedDict[str, tuple[bytes, float]] = OrderedDict()
        self._max_size = max_size

    def _key(self, data: bytes) -> str:
        # Hash everything after the TX ID (so different IDs for same query hit cache)
        return hashlib.md5(data[2:]).hexdigest()

    def get(self, query: bytes) -> Optional[bytes]:
        key = self._key(query)
        entry = self._cache.get(key)
        if entry is None:
            return None
        response, expires = entry
        if time.monotonic() > expires:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        # Patch the TX ID to match this query
        return query[:2] + response[2:]

    def put(self, query: bytes, response: bytes, ttl: int):
        key = self._key(query)
        self._cache[key] = (response, time.monotonic() + ttl)
        self._cache.move_to_end(key)
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)


# ── Upstream Resolver ──

async def forward_upstream_udp(
    query: bytes,
    upstreams: list[str] = None,
    timeout: float = config.DNS_UPSTREAM_TIMEOUT,
) -> Optional[bytes]:
    """Forward a DNS query to upstream resolvers via plain UDP."""
    upstreams = upstreams or config.DNS_UPSTREAM

    loop = asyncio.get_running_loop()

    for server in upstreams:
        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    lambda: _UpstreamProtocol(),
                    remote_addr=(server, config.DNS_UPSTREAM_PORT),
                ),
                timeout=timeout,
            )

            try:
                transport.sendto(query)
                response = await asyncio.wait_for(
                    protocol.response_future, timeout=timeout
                )
                return response
            finally:
                transport.close()

        except (asyncio.TimeoutError, OSError) as e:
            logger.debug("UDP upstream %s failed: %s", server, e)
            continue

    logger.warning("All UDP upstream DNS servers failed")
    return None


async def forward_upstream_doh(
    query: bytes,
    upstreams: list[str] = None,
    timeout: float = None,
) -> Optional[bytes]:
    """
    Forward a DNS query via DNS-over-HTTPS (RFC 8484).
    Sends the raw DNS wireformat as application/dns-message POST body.
    The DoH server returns the raw DNS response bytes.
    """
    import aiohttp

    upstreams = upstreams or config.DOH_UPSTREAM
    timeout = timeout or config.DOH_TIMEOUT

    for server_url in upstreams:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.post(
                    server_url,
                    data=query,
                    headers={
                        "Content-Type": "application/dns-message",
                        "Accept": "application/dns-message",
                    },
                ) as resp:
                    if resp.status == 200:
                        return await resp.read()
                    else:
                        logger.debug("DoH %s returned HTTP %d", server_url, resp.status)

        except (asyncio.TimeoutError, Exception) as e:
            logger.debug("DoH upstream %s failed: %s", server_url, e)
            continue

    logger.warning("All DoH upstream servers failed")
    return None


async def forward_upstream(
    query: bytes,
    upstreams: list[str] = None,
    timeout: float = config.DNS_UPSTREAM_TIMEOUT,
) -> Optional[bytes]:
    """
    Forward a DNS query upstream. Uses DoH if enabled, falls back to UDP.
    """
    if config.DOH_ENABLED:
        result = await forward_upstream_doh(query)
        if result:
            return result
        # DoH failed — fall back to plain UDP
        logger.debug("DoH failed, falling back to UDP")

    return await forward_upstream_udp(query, upstreams, timeout)


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """One-shot UDP protocol to receive a single upstream DNS response."""

    def __init__(self):
        self.response_future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple):
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc: Exception):
        if not self.response_future.done():
            self.response_future.set_exception(exc)


# ── DNS Protocol Handler ──

class DNSServerProtocol(asyncio.DatagramProtocol):
    """
    asyncio UDP protocol for the DNS proxy.
    Receives queries, checks blocklist, and responds.
    """

    def __init__(self, blocklist_set: set, traffic_callback=None):
        self.blocklist = blocklist_set
        self.cache = DNSCache()
        self.transport = None
        self.traffic_callback = traffic_callback
        self.blocking_enabled = True  # Engine toggle — can be flipped via API
        self._stats = {
            "queries": 0, "blocked": 0, "forwarded": 0, "cached": 0,
            "doh_enabled": config.DOH_ENABLED, "blocking_enabled": True,
        }
        # Ring buffers for live dashboard — instant feedback, no DB delay
        self._recent_blocked: list[dict] = []
        self._recent_allowed: list[dict] = []
        self._max_recent = 50

        # Full query log for advanced reporting (last 200 entries)
        self._query_log: list[dict] = []
        self._max_log = 200

        # In-memory aggregations for instant reporting
        self._domain_block_counts: dict[str, int] = {}     # domain → count
        self._domain_allow_counts: dict[str, int] = {}     # domain → count
        self._client_query_counts: dict[str, int] = {}     # client_ip → total queries
        self._client_block_counts: dict[str, int] = {}     # client_ip → blocked queries
        self._client_last_seen: dict[str, float] = {}      # client_ip → timestamp
        self._qtype_counts: dict[str, int] = {}            # qtype → count
        self._hourly_blocks: dict[int, int] = {}           # hour_of_day → blocked count
        self._hourly_total: dict[int, int] = {}            # hour_of_day → total count

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    def _record_event(self, client_ip: str, domain: str, qtype: str,
                      blocked: bool, matched_rule: str, resolution: str,
                      latency_ms: float):
        """Record a DNS event for live dashboard and reporting."""
        import time as _time
        now = _time.time()
        hour = int((_time.localtime(now).tm_hour))

        entry = {
            "domain": domain,
            "client": client_ip,
            "qtype": qtype,
            "blocked": blocked,
            "matched_rule": matched_rule,
            "resolution": resolution,
            "latency_ms": round(latency_ms, 2),
            "time": now,
        }

        # Live feeds
        if blocked:
            self._recent_blocked.append(entry)
            if len(self._recent_blocked) > self._max_recent:
                self._recent_blocked.pop(0)
        else:
            self._recent_allowed.append(entry)
            if len(self._recent_allowed) > self._max_recent:
                self._recent_allowed.pop(0)

        # Full log
        self._query_log.append(entry)
        if len(self._query_log) > self._max_log:
            self._query_log.pop(0)

        # Aggregations
        if blocked:
            self._domain_block_counts[domain] = self._domain_block_counts.get(domain, 0) + 1
            self._client_block_counts[client_ip] = self._client_block_counts.get(client_ip, 0) + 1
            self._hourly_blocks[hour] = self._hourly_blocks.get(hour, 0) + 1
        else:
            self._domain_allow_counts[domain] = self._domain_allow_counts.get(domain, 0) + 1

        self._client_query_counts[client_ip] = self._client_query_counts.get(client_ip, 0) + 1
        self._client_last_seen[client_ip] = now
        self._qtype_counts[qtype] = self._qtype_counts.get(qtype, 0) + 1
        self._hourly_total[hour] = self._hourly_total.get(hour, 0) + 1

    async def _handle(self, data: bytes, addr: tuple):
        import time as _time
        start_time = _time.monotonic()

        self._stats["queries"] += 1

        query_info = extract_query_info(data)
        domain = query_info["name"] if query_info else extract_query_name(data)
        qtype = query_info["qtype"] if query_info else "?"

        if domain is None:
            return

        client_ip = addr[0]

        # Check blocklist (only if blocking engine is enabled)
        blocked = False
        matched_rule = ""
        if self.blocking_enabled:
            parts = domain.split(".")
            for i in range(len(parts) - 1):
                candidate = ".".join(parts[i:])
                if candidate in self.blocklist:
                    blocked = True
                    matched_rule = candidate
                    break

        if blocked:
            self._stats["blocked"] += 1
            response = build_blocked_response(data)
            self.transport.sendto(response, addr)
            elapsed = (_time.monotonic() - start_time) * 1000
            self._record_event(client_ip, domain, qtype, True, matched_rule, "NXDOMAIN", elapsed)
            if self.traffic_callback:
                self.traffic_callback(client_ip, domain, blocked=True)
            return

        # Check cache
        cached = self.cache.get(data)
        if cached:
            self._stats["cached"] += 1
            self.transport.sendto(cached, addr)
            elapsed = (_time.monotonic() - start_time) * 1000
            self._record_event(client_ip, domain, qtype, False, "", "CACHED", elapsed)
            if self.traffic_callback:
                self.traffic_callback(client_ip, domain, blocked=False)
            return

        # Forward upstream (DoH or UDP depending on config)
        self._stats["forwarded"] += 1
        response = await forward_upstream(data)
        if response:
            self.cache.put(data, response, ttl=config.DNS_CACHE_TTL)
            self.transport.sendto(response, addr)

        elapsed = (_time.monotonic() - start_time) * 1000
        resolution = "RESOLVED" if response else "FAILED"
        self._record_event(client_ip, domain, qtype, False, "", resolution, elapsed)
        if self.traffic_callback:
            self.traffic_callback(client_ip, domain, blocked=False)

    def set_blocking(self, enabled: bool):
        """Toggle the blocking engine on or off."""
        self.blocking_enabled = enabled
        self._stats["blocking_enabled"] = enabled
        logger.info("Blocking engine %s", "ENABLED" if enabled else "DISABLED")

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ── Server Lifecycle ──

async def start_dns_server(
    blocklist: set,
    traffic_callback=None,
    host: str = config.DNS_LISTEN_HOST,
    port: int = config.DNS_LISTEN_PORT,
) -> tuple[asyncio.DatagramTransport, DNSServerProtocol]:
    """Start the DNS proxy server. Returns (transport, protocol)."""
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(blocklist, traffic_callback),
        local_addr=(host, port),
    )

    logger.info("DNS proxy listening on %s:%d (%d domains blocked)", host, port, len(blocklist))
    return transport, protocol
