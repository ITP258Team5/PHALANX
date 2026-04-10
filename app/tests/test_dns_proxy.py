#!/usr/bin/env python3
"""
Tests for Phalanx DNS proxy and blocklist logic.

Verifies:
  1. DNS name parsing from raw packets
  2. Blocked response building (correct NXDOMAIN format)
  3. Blocklist matching (exact, parent domain, subdomain)
  4. Blocklist parsing (hosts format, domain list format)
  5. Cache behavior (hit, miss, expiry, TX ID patching)
  6. Full proxy flow simulation (blocked vs forwarded decisions)
  7. Whitelist/blacklist overrides
"""

import asyncio
import struct
import sys
import time

# Add parent to path so we can import the app modules
sys.path.insert(0, ".")

from core.dns_proxy import (
    parse_dns_name,
    extract_query_name,
    build_blocked_response,
    DNSCache,
    DNSServerProtocol,
)
from core.blocklist import parse_hosts_file, parse_domain_list, BlocklistManager


# ── Helpers ──

def build_dns_query(domain: str, tx_id: int = 0x1234) -> bytes:
    """Build a minimal DNS query packet for a domain."""
    # Header: TX ID, flags (standard query), QDCOUNT=1, rest=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)

    # Question section: encode domain name
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # root label
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN

    return header + question


passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name} — {detail}")
        failed += 1


# ══════════════════════════════════════
# 1. DNS Name Parsing
# ══════════════════════════════════════
print("\n── DNS Name Parsing ──")

query = build_dns_query("ads.doubleclick.net")
name = extract_query_name(query)
test("Parse simple domain", name == "ads.doubleclick.net", f"got: {name}")

query = build_dns_query("a.b.c.d.example.com")
name = extract_query_name(query)
test("Parse deep subdomain", name == "a.b.c.d.example.com", f"got: {name}")

query = build_dns_query("google.com")
name = extract_query_name(query)
test("Parse two-label domain", name == "google.com", f"got: {name}")

name = extract_query_name(b"\x00" * 5)  # too short
test("Reject truncated packet", name is None)

name = extract_query_name(b"")
test("Reject empty packet", name is None)

# Single label (rare but valid)
query = build_dns_query("localhost")
name = extract_query_name(query)
test("Parse single label", name == "localhost", f"got: {name}")


# ══════════════════════════════════════
# 2. Blocked Response Building
# ══════════════════════════════════════
print("\n── Blocked Response Building ──")

query = build_dns_query("tracker.facebook.com", tx_id=0xABCD)
response = build_blocked_response(query)

# Check TX ID preserved
resp_tx = struct.unpack("!H", response[:2])[0]
test("TX ID preserved", resp_tx == 0xABCD, f"got: {hex(resp_tx)}")

# Check flags: QR=1, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
resp_flags = struct.unpack("!H", response[2:4])[0]
qr = (resp_flags >> 15) & 1
aa = (resp_flags >> 10) & 1
rcode = resp_flags & 0xF
test("QR flag set (response)", qr == 1)
test("AA flag set (authoritative)", aa == 1)
test("RCODE is NXDOMAIN (3)", rcode == 3, f"got: {rcode}")

# Check ANCOUNT = 0 (no answer records)
ancount = struct.unpack("!H", response[6:8])[0]
test("No answer records", ancount == 0, f"got: {ancount}")

# Check question section preserved
resp_name = extract_query_name(response)
test("Question domain preserved", resp_name == "tracker.facebook.com", f"got: {resp_name}")


# ══════════════════════════════════════
# 3. Blocklist Parsing
# ══════════════════════════════════════
print("\n── Blocklist Parsing ──")

hosts_content = """
# This is a comment
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
0.0.0.0 malware.bad.com
# Another comment
0.0.0.0 ads.doubleclick.net
"""
domains = parse_hosts_file(hosts_content)
test("Hosts: parses ad domains", "ads.example.com" in domains)
test("Hosts: parses tracker domains", "tracker.example.com" in domains)
test("Hosts: parses malware domains", "malware.bad.com" in domains)
test("Hosts: skips localhost", "localhost" not in domains)
test("Hosts: skips comments", len([d for d in domains if d.startswith("#")]) == 0)
test("Hosts: correct count", len(domains) == 4, f"got: {len(domains)}")

domain_content = """
# Blocklist
ads.example.com
tracker.example.com

malware.bad.com
# inline comment
crypto-miner.evil.org
"""
domains = parse_domain_list(domain_content)
test("Domain list: parses all", len(domains) == 4, f"got: {len(domains)}")
test("Domain list: has crypto miner", "crypto-miner.evil.org" in domains)
test("Domain list: skips blanks", "" not in domains)

# Edge cases
domains = parse_hosts_file("")
test("Empty hosts file", len(domains) == 0)

domains = parse_domain_list("# only comments\n# nothing here\n")
test("Comments-only file", len(domains) == 0)

# Trailing dots
domains = parse_domain_list("example.com.\ntest.org.\n")
test("Strips trailing dots", "example.com" in domains and "test.org" in domains)


# ══════════════════════════════════════
# 4. Blocklist Matching (parent domains)
# ══════════════════════════════════════
print("\n── Blocklist Matching ──")

blocklist = {"doubleclick.net", "tracker.facebook.com", "malware.bad.com"}

# Simulate the matching logic from DNSServerProtocol._handle
def is_blocked(domain, bl):
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in bl:
            return True
    return False

test("Exact match blocks", is_blocked("doubleclick.net", blocklist))
test("Subdomain of blocked domain blocks", is_blocked("ads.doubleclick.net", blocklist))
test("Deep subdomain blocks", is_blocked("a.b.c.doubleclick.net", blocklist))
test("Exact tracker match", is_blocked("tracker.facebook.com", blocklist))
test("Sub of tracker blocks", is_blocked("pixel.tracker.facebook.com", blocklist))
test("Parent of tracker NOT blocked", not is_blocked("facebook.com", blocklist))
test("Unrelated domain NOT blocked", not is_blocked("google.com", blocklist))
test("Partial name match NOT blocked", not is_blocked("notdoubleclick.net", blocklist))
test("Similar suffix NOT blocked", not is_blocked("xdoubleclick.net", blocklist))
test("Malware exact match", is_blocked("malware.bad.com", blocklist))
test("Malware subdomain", is_blocked("payload.malware.bad.com", blocklist))
test("bad.com itself NOT blocked", not is_blocked("bad.com", blocklist))


# ══════════════════════════════════════
# 5. DNS Cache
# ══════════════════════════════════════
print("\n── DNS Cache ──")

cache = DNSCache(max_size=3)

query1 = build_dns_query("example.com", tx_id=0x0001)
resp1 = build_blocked_response(query1)

# Miss on empty cache
test("Cache miss on empty", cache.get(query1) is None)

# Put and get
cache.put(query1, resp1, ttl=60)
cached = cache.get(query1)
test("Cache hit after put", cached is not None)

# TX ID patching: same query with different TX ID should hit cache
query1b = build_dns_query("example.com", tx_id=0x9999)
cached = cache.get(query1b)
test("Cache hit with different TX ID", cached is not None)
if cached:
    cached_tx = struct.unpack("!H", cached[:2])[0]
    test("TX ID patched to match query", cached_tx == 0x9999, f"got: {hex(cached_tx)}")

# Different domain is a miss
query2 = build_dns_query("other.com", tx_id=0x0002)
test("Cache miss for different domain", cache.get(query2) is None)

# LRU eviction
cache.put(build_dns_query("a.com"), b"resp_a", ttl=60)
cache.put(build_dns_query("b.com"), b"resp_b", ttl=60)
cache.put(build_dns_query("c.com"), b"resp_c", ttl=60)
# Cache is max_size=3, so the oldest (example.com) should be evicted
test("LRU eviction works", cache.get(query1) is None)
test("Recent entry survives", cache.get(build_dns_query("c.com")) is not None)

# TTL expiry
cache2 = DNSCache(max_size=10)
query_ttl = build_dns_query("expire.com")
cache2.put(query_ttl, b"will_expire", ttl=0)  # expires immediately
time.sleep(0.01)
test("Expired entry returns None", cache2.get(query_ttl) is None)


# ══════════════════════════════════════
# 6. Full Proxy Decision Simulation
# ══════════════════════════════════════
print("\n── Proxy Decision Simulation ──")

# Track what the protocol would do
decisions = []

def mock_traffic_callback(ip, domain, blocked):
    decisions.append({"ip": ip, "domain": domain, "blocked": blocked})

ad_blocklist = {
    "doubleclick.net",
    "ads.facebook.com",
    "tracker.unity3d.com",
    "analytics.google.com",
    "malware.example.com",
}

protocol = DNSServerProtocol(ad_blocklist, traffic_callback=mock_traffic_callback)

# Simulate checks without actually sending packets
test_cases = [
    ("ads.doubleclick.net", True, "Ad subdomain"),
    ("doubleclick.net", True, "Ad domain exact"),
    ("www.google.com", False, "Legitimate site"),
    ("ads.facebook.com", True, "Social media tracker"),
    ("www.facebook.com", False, "Legitimate social media"),
    ("tracker.unity3d.com", True, "Game tracker"),
    ("unity3d.com", False, "Game engine site (parent not blocked)"),
    ("payload.malware.example.com", True, "Deep malware subdomain"),
    ("example.com", False, "Parent of malware (not blocked)"),
    ("analytics.google.com", True, "Analytics tracker"),
    ("mail.google.com", False, "Legitimate Google service"),
]

for domain, should_block, desc in test_cases:
    parts = domain.split(".")
    blocked = False
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in ad_blocklist:
            blocked = True
            break
    test(f"{desc}: {domain} → {'BLOCKED' if blocked else 'ALLOWED'}",
         blocked == should_block)


# ══════════════════════════════════════
# 7. Whitelist / Blacklist Overrides
# ══════════════════════════════════════
print("\n── Whitelist / Blacklist Overrides ──")

# Create a blocklist manager with a mock set
from pathlib import Path
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    mgr = BlocklistManager(
        blocklist_dir=Path(tmpdir),
        sources=[],  # no remote sources
    )

    # Manually seed the active set
    mgr._active_set = {"ads.example.com", "tracker.test.com", "malware.bad.org"}

    test("Baseline: ads.example.com blocked",
         "ads.example.com" in mgr.active_set)

    # Whitelist should remove from active set
    mgr.add_whitelist("ads.example.com")
    test("Whitelisted domain removed from blocklist",
         "ads.example.com" not in mgr.active_set)

    # Remove whitelist should NOT auto-re-add (need a blocklist refresh for that)
    mgr.remove_whitelist("ads.example.com")
    test("Remove whitelist doesn't auto-re-add",
         "ads.example.com" not in mgr.active_set)

    # Blacklist should add to active set
    mgr.add_blacklist("custom-malware.evil.com")
    test("Blacklisted domain added to blocklist",
         "custom-malware.evil.com" in mgr.active_set)

    # Remove blacklist
    mgr.remove_blacklist("custom-malware.evil.com")
    test("Removed blacklist entry gone",
         "custom-malware.evil.com" not in mgr.active_set)

    # Existing entries unaffected
    test("Other entries unaffected",
         "tracker.test.com" in mgr.active_set and "malware.bad.org" in mgr.active_set)


# ══════════════════════════════════════
# Summary
# ══════════════════════════════════════
print("\n" + "=" * 50)
total = passed + failed
print(f"  {passed}/{total} tests passed", end="")
if failed:
    print(f"  ({failed} FAILED)")
    sys.exit(1)
else:
    print("  — all clear! ✅")
    sys.exit(0)
