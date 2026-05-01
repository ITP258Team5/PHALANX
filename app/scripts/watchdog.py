#!/usr/bin/env python3
"""
Phalanx Watchdog — DNS Health Monitor & Failsafe

Runs as a separate systemd service. Every 10 seconds:
  1. Sends a test DNS query through Phalanx (port 53)
  2. If it fails 3 times in a row → restart the Phalanx service
  3. If restart fails → switch DHCP to advertise fallback DNS
  4. When Phalanx recovers → re-advertise Pi as primary DNS

This ensures the network never loses DNS even if Phalanx crashes.

Install:
  sudo cp phalanx-watchdog.service /etc/systemd/system/
  sudo systemctl enable phalanx-watchdog
  sudo systemctl start phalanx-watchdog
"""

import logging
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

# ── Configuration ──
CHECK_INTERVAL = 10          # seconds between health checks
FAILURE_THRESHOLD = 3        # consecutive failures before action
RESTART_COOLDOWN = 60        # seconds between restart attempts
TEST_DOMAIN = "cloudflare.com"  # domain to test (must not be on blocklist)
DNS_HOST = "127.0.0.1"
DNS_PORT = 53
PHALANX_SERVICE = "phalanx"
DNSMASQ_CONF = Path("/etc/dnsmasq.conf")
DNSMASQ_CONF_BACKUP = Path("/etc/dnsmasq.conf.bak.watchdog")
LOG_DIR = Path("/var/log/phalanx")
FALLBACK_DNS = "1.1.1.1"

# ── Logging ──
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [watchdog] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "watchdog.log", mode="a"),
    ],
)
log = logging.getLogger("phalanx.watchdog")


def build_dns_query(domain: str) -> bytes:
    """Build a minimal DNS A query."""
    tx_id = struct.pack("!H", int(time.time()) % 65535)
    flags = struct.pack("!H", 0x0100)  # standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)  # 1 question

    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN

    return tx_id + flags[0:1] + flags[1:2] + counts + question


def check_dns_health() -> bool:
    """Send a UDP DNS query to localhost:53 and check for a response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)

        query = build_dns_query(TEST_DOMAIN)
        sock.sendto(query, (DNS_HOST, DNS_PORT))

        response, _ = sock.recvfrom(512)
        sock.close()

        # Check we got a valid response (at least 12 bytes, QR bit set)
        if len(response) < 12:
            return False

        flags = struct.unpack("!H", response[2:4])[0]
        qr = (flags >> 15) & 1
        rcode = flags & 0xF

        # QR=1 means response, RCODE 0=NOERROR or 3=NXDOMAIN are both "working"
        return qr == 1 and rcode in (0, 3)

    except (socket.timeout, OSError, Exception) as e:
        log.debug("DNS health check failed: %s", e)
        return False


def restart_phalanx() -> bool:
    """Attempt to restart the Phalanx service."""
    log.warning("Restarting Phalanx service...")
    try:
        result = subprocess.run(
            ["systemctl", "restart", PHALANX_SERVICE],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info("Phalanx service restarted successfully")
            time.sleep(5)  # Give it time to bind port 53
            return check_dns_health()
        else:
            log.error("Restart failed: %s", result.stderr.strip())
            return False
    except Exception as e:
        log.error("Restart exception: %s", e)
        return False


def switch_to_fallback():
    """
    Modify dnsmasq config to advertise fallback DNS instead of Pi.
    This ensures all devices on the network still have working DNS
    even though Phalanx is down.
    """
    if not DNSMASQ_CONF.exists():
        log.warning("dnsmasq not configured — cannot switch to fallback")
        return

    log.warning("FAILSAFE: Switching network DNS to fallback (%s)", FALLBACK_DNS)

    # Back up current config
    if not DNSMASQ_CONF_BACKUP.exists():
        DNSMASQ_CONF_BACKUP.write_text(DNSMASQ_CONF.read_text())

    # Read and modify
    content = DNSMASQ_CONF.read_text()

    # Replace the dns-server option to put fallback first
    import re
    content = re.sub(
        r"dhcp-option=option:dns-server,.*",
        f"dhcp-option=option:dns-server,{FALLBACK_DNS}",
        content,
    )

    DNSMASQ_CONF.write_text(content)

    # Restart dnsmasq to push new leases
    subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True, timeout=10)
    log.warning("FAILSAFE: dnsmasq now advertising %s as DNS", FALLBACK_DNS)


def switch_to_phalanx(pi_ip: str):
    """
    Restore dnsmasq config to advertise Pi as primary DNS.
    Called when Phalanx recovers after a failover.
    """
    if not DNSMASQ_CONF_BACKUP.exists():
        return

    log.info("RECOVERY: Restoring Phalanx as primary DNS")

    # Restore original config
    DNSMASQ_CONF.write_text(DNSMASQ_CONF_BACKUP.read_text())
    DNSMASQ_CONF_BACKUP.unlink()

    subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True, timeout=10)
    log.info("RECOVERY: dnsmasq now advertising %s as DNS", pi_ip)


def get_pi_ip() -> str:
    """Get the Pi's current IP address."""
    try:
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().split()[0]
    except Exception:
        return "127.0.0.1"


def check_phalanx_api() -> bool:
    """Check if the Phalanx API is responding."""
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:80/health", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        # Try the dashboard endpoint instead
        try:
            req = urllib.request.Request("http://127.0.0.1:80/api/dashboard", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False


def main():
    log.info("Phalanx Watchdog starting")
    log.info("Monitoring DNS on %s:%d every %ds", DNS_HOST, DNS_PORT, CHECK_INTERVAL)

    consecutive_failures = 0
    last_restart_time = 0
    in_failover = False
    pi_ip = get_pi_ip()

    while True:
        try:
            healthy = check_dns_health()

            if healthy:
                if consecutive_failures > 0:
                    log.info("DNS recovered after %d failures", consecutive_failures)
                consecutive_failures = 0

                # If we were in failover mode, restore Phalanx as primary DNS
                if in_failover:
                    switch_to_phalanx(pi_ip)
                    in_failover = False

            else:
                consecutive_failures += 1
                log.warning("DNS health check failed (%d/%d)",
                           consecutive_failures, FAILURE_THRESHOLD)

                if consecutive_failures >= FAILURE_THRESHOLD:
                    now = time.time()

                    # Try restarting (with cooldown)
                    if now - last_restart_time > RESTART_COOLDOWN:
                        last_restart_time = now
                        if restart_phalanx():
                            consecutive_failures = 0
                            log.info("Phalanx recovered after restart")
                        else:
                            # Restart didn't fix it — engage failsafe
                            if not in_failover:
                                switch_to_fallback()
                                in_failover = True
                                log.error(
                                    "Phalanx unrecoverable. Network using fallback DNS. "
                                    "Will keep trying to restart."
                                )
                    else:
                        remaining = int(RESTART_COOLDOWN - (now - last_restart_time))
                        log.debug("Restart cooldown: %ds remaining", remaining)

        except Exception as e:
            log.error("Watchdog loop error: %s", e)

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
