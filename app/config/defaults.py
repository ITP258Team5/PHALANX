"""
Project Phalanx — Default Configuration
Tuned for Raspberry Pi 4 (4GB RAM)
"""

import os
from pathlib import Path

# ── Paths ──
BASE_DIR = Path(os.getenv("PHALANX_BASE", "/opt/phalanx"))
DATA_DIR = BASE_DIR / "data"
BLOCKLIST_DIR = BASE_DIR / "blocklists"
DB_PATH = DATA_DIR / "phalanx.db"
LOG_DIR = BASE_DIR / "logs"

# ── DNS Proxy ──
DNS_LISTEN_HOST = "0.0.0.0"
DNS_LISTEN_PORT = 53
DNS_UPSTREAM = ["1.1.1.1", "8.8.8.8"]  # Cloudflare + Google fallback
DNS_UPSTREAM_PORT = 53
DNS_UPSTREAM_TIMEOUT = 3.0  # seconds
DNS_CACHE_MAX_SIZE = 8192  # entries — ~2MB at ~250 bytes/entry
DNS_CACHE_TTL = 300  # seconds, for blocked responses

# ── Blocklist ──
BLOCKLIST_SOURCES = [
    # Free defaults that ship with the device (always active)
    {
        "name": "StevenBlack Unified",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "subscription_required": False,
    },
    {
        "name": "Phalanx Curated",
        "url": "",  # Populated by subscription service
        "format": "domains",
        "subscription_required": True,
    },
]
BLOCKLIST_UPDATE_INTERVAL = 86400  # 24 hours (subscription)
BLOCKLIST_STALE_THRESHOLD = 90  # days before warning user
BLOCKLIST_FROZEN_MSG = (
    "Your blocklist hasn't been updated in {days} days. "
    "Renew your subscription to stay protected."
)

# ── Subscription ──
SUBSCRIPTION_API_URL = os.getenv(
    "PHALANX_SUB_API", "https://api.phalanx.example.com/v1"
)
SUBSCRIPTION_CHECK_INTERVAL = 3600  # re-validate every hour
SUBSCRIPTION_GRACE_PERIOD = 7  # days after expiry before freezing lists

# ── Traffic Monitor ──
MONITOR_BASELINE_WINDOW = 72  # hours to build per-device baseline
MONITOR_ANOMALY_THRESHOLD = 3.0  # std deviations above baseline
MONITOR_BATCH_INTERVAL = 60  # aggregate stats every N seconds
MONITOR_MAX_LOG_ROWS = 500_000  # rotate after this many rows in DB

# ── API Server ──
API_HOST = "0.0.0.0"
API_PORT = 80
API_SECRET_KEY = os.getenv("PHALANX_SECRET", "CHANGE_ME_ON_FIRST_BOOT")
API_SESSION_TTL = 86400  # 24 hours

# ── Alerting ──
ALERT_SUPPRESSION_WINDOW = 300  # group duplicate alerts within 5 min
ALERT_QUIET_SEVERITIES = ["low"]  # hide from main dashboard by default
ALERT_MAX_STORED = 10_000

# ── Resource Limits (Pi 4 / 4GB) ──
MAX_MEMORY_MB = 256  # soft target for total process RSS
WORKER_THREADS = 2  # for blocking I/O (disk, upstream DNS)
