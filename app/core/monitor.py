"""
Phalanx Traffic Monitor

Tracks per-device DNS activity, builds behavioral baselines, detects
anomalies, and groups alerts to reduce noise.

Refactored to use core.database for all DB access — no more inline
schema definitions.
"""

import asyncio
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import config
from core.database import get_connection, transaction

logger = logging.getLogger("phalanx.monitor")


@dataclass
class DeviceStats:
    """Rolling stats for a single device within the current batch window."""
    ip: str
    queries: int = 0
    blocked: int = 0
    unique_domains: set = field(default_factory=set)
    block_reasons: dict = field(default_factory=lambda: defaultdict(int))
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class Alert:
    id: Optional[int] = None
    severity: str = "low"
    device_ip: str = ""
    device_name: str = ""
    message: str = ""
    details: str = ""
    timestamp: float = 0.0
    acknowledged: bool = False
    alert_group: str = ""


class TrafficMonitor:
    """
    Collects DNS query events, aggregates per-device stats, builds
    baselines, and fires alerts on anomalies.
    """

    def __init__(self):
        self._current_batch: dict[str, DeviceStats] = {}
        self._batch_start = time.time()
        self._device_names: dict[str, str] = {}
        self._suppressed: dict[str, float] = {}
        self._load_device_names()

    def _load_device_names(self):
        """Load cached device names from DB on startup."""
        try:
            conn = get_connection()
            cursor = conn.execute("SELECT ip, name FROM devices WHERE name != ''")
            for row in cursor:
                self._device_names[row["ip"]] = row["name"]
        except Exception as e:
            logger.debug("Could not preload device names: %s", e)

    def record_query(self, client_ip: str, domain: str, blocked: bool = False):
        """Called by DNS proxy for every query. Batches in memory."""
        now = time.time()

        if client_ip not in self._current_batch:
            self._current_batch[client_ip] = DeviceStats(ip=client_ip, first_seen=now)

        stats = self._current_batch[client_ip]
        stats.queries += 1
        if blocked:
            stats.blocked += 1
        stats.unique_domains.add(domain)
        stats.last_seen = now

    async def flush_batch(self):
        """Write current batch to SQLite and check for anomalies."""
        if not self._current_batch:
            return

        batch = self._current_batch
        self._current_batch = {}
        now = time.time()

        conn = get_connection()

        with transaction(conn):
            for ip, stats in batch.items():
                for domain in stats.unique_domains:
                    was_blocked = 1 if stats.blocked > 0 else 0
                    conn.execute(
                        """INSERT INTO traffic_log
                           (timestamp, device_ip, domain, blocked, block_reason)
                           VALUES (?, ?, ?, ?, ?)""",
                        (stats.last_seen, ip, domain, was_blocked, ""),
                    )

                conn.execute(
                    """INSERT INTO devices (ip, first_seen, last_seen)
                       VALUES (?, ?, ?)
                       ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen""",
                    (ip, stats.first_seen, stats.last_seen),
                )

        alerts = self._check_anomalies(batch, conn)
        if alerts:
            with transaction(conn):
                for alert in alerts:
                    self._store_alert(alert, conn)

        cutoff = now - (config.MONITOR_BASELINE_WINDOW * 3600 * 2)
        conn.execute("DELETE FROM traffic_log WHERE timestamp < ?", (cutoff,))
        conn.commit()

        self._batch_start = now

    def _check_anomalies(self, batch: dict[str, DeviceStats], conn) -> list[Alert]:
        """Compare current batch against device baselines."""
        alerts = []
        now = time.time()

        for ip, stats in batch.items():
            row = conn.execute(
                "SELECT * FROM device_baselines WHERE device_ip = ?", (ip,)
            ).fetchone()

            if row is None:
                continue

            avg_q = row["avg_queries_per_hour"]
            std_q = row["std_queries_per_hour"]
            known_str = row["known_domains"] or ""
            known = set(known_str.split(",")) if known_str else set()

            window_hours = max(config.MONITOR_BATCH_INTERVAL / 3600, 0.001)
            rate_q = stats.queries / window_hours
            threshold = config.MONITOR_ANOMALY_THRESHOLD
            device_name = self._device_names.get(ip, ip)

            if std_q > 0 and rate_q > avg_q + (threshold * std_q):
                alert_key = f"query_spike:{ip}"
                if self._should_alert(alert_key, now):
                    alerts.append(Alert(
                        severity="medium",
                        device_ip=ip,
                        device_name=device_name,
                        message=f"Unusual query volume: {stats.queries} queries in the last minute (normal: ~{int(avg_q * window_hours)})",
                        timestamp=now,
                        alert_group=alert_key,
                    ))

            new_domains = stats.unique_domains - known
            if len(new_domains) > 5:
                alert_key = f"new_domains:{ip}"
                if self._should_alert(alert_key, now):
                    sample = list(new_domains)[:3]
                    alerts.append(Alert(
                        severity="medium" if len(new_domains) < 20 else "high",
                        device_ip=ip,
                        device_name=device_name,
                        message=f"Contacted {len(new_domains)} previously unseen domains",
                        details=f"Examples: {', '.join(sample)}",
                        timestamp=now,
                        alert_group=alert_key,
                    ))

        return alerts

    def _should_alert(self, key: str, now: float) -> bool:
        last = self._suppressed.get(key, 0)
        if now - last < config.ALERT_SUPPRESSION_WINDOW:
            return False
        self._suppressed[key] = now
        return True

    def _store_alert(self, alert: Alert, conn):
        conn.execute(
            """INSERT INTO alerts
               (severity, device_ip, device_name, message, details, timestamp, alert_group)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (alert.severity, alert.device_ip, alert.device_name,
             alert.message, alert.details, alert.timestamp, alert.alert_group),
        )
        logger.warning("ALERT [%s] %s: %s", alert.severity, alert.device_ip, alert.message)

    async def rebuild_baselines(self):
        """Recalculate per-device baselines from stored traffic logs."""
        conn = get_connection()
        now = time.time()
        window_start = now - (config.MONITOR_BASELINE_WINDOW * 3600)

        devices = [
            row["device_ip"]
            for row in conn.execute(
                "SELECT DISTINCT device_ip FROM traffic_log WHERE timestamp > ?",
                (window_start,),
            )
        ]

        with transaction(conn):
            for ip in devices:
                rows = conn.execute(
                    """SELECT CAST((timestamp - ?) / 3600 AS INTEGER) AS hour_bucket,
                              COUNT(*) AS cnt,
                              COUNT(DISTINCT domain) AS unique_doms
                       FROM traffic_log
                       WHERE device_ip = ? AND timestamp > ?
                       GROUP BY hour_bucket""",
                    (window_start, ip, window_start),
                ).fetchall()

                if len(rows) < 3:
                    continue

                counts = [r["cnt"] for r in rows]
                dom_counts = [r["unique_doms"] for r in rows]

                avg_q = sum(counts) / len(counts)
                std_q = (
                    math.sqrt(sum((x - avg_q) ** 2 for x in counts) / len(counts))
                    if len(counts) > 1 else 0
                )
                avg_d = sum(dom_counts) / len(dom_counts)
                std_d = (
                    math.sqrt(sum((x - avg_d) ** 2 for x in dom_counts) / len(dom_counts))
                    if len(dom_counts) > 1 else 0
                )

                known_rows = conn.execute(
                    "SELECT DISTINCT domain FROM traffic_log WHERE device_ip = ? AND timestamp > ?",
                    (ip, window_start),
                ).fetchall()
                known_str = ",".join(r["domain"] for r in known_rows[:5000])

                conn.execute(
                    """INSERT INTO device_baselines
                           (device_ip, avg_queries_per_hour, std_queries_per_hour,
                            avg_unique_domains_per_hour, std_unique_domains_per_hour,
                            known_domains, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(device_ip) DO UPDATE SET
                           avg_queries_per_hour = excluded.avg_queries_per_hour,
                           std_queries_per_hour = excluded.std_queries_per_hour,
                           avg_unique_domains_per_hour = excluded.avg_unique_domains_per_hour,
                           std_unique_domains_per_hour = excluded.std_unique_domains_per_hour,
                           known_domains = excluded.known_domains,
                           updated_at = excluded.updated_at""",
                    (ip, avg_q, std_q, avg_d, std_d, known_str, now),
                )

        logger.info("Rebuilt baselines for %d devices", len(devices))

    def set_device_name(self, ip: str, name: str):
        self._device_names[ip] = name
        conn = get_connection()
        conn.execute("UPDATE devices SET name = ? WHERE ip = ?", (name, ip))
        conn.commit()

    def get_alerts(self, limit: int = 50, include_low: bool = False) -> list[dict]:
        conn = get_connection()
        if include_low:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity != 'low' ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_device_summary(self) -> list[dict]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [
            {
                "ip": r["ip"],
                "mac": r["mac"],
                "name": r["name"] or r["ip"],
                "device_type": r["device_type"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "is_blocked": bool(r["is_blocked"]),
            }
            for r in rows
        ]

    def get_grouped_alerts(self, limit: int = 20) -> list[dict]:
        """
        Get alerts collapsed by alert_group. Returns the most recent
        alert per group with a count of how many were suppressed.
        """
        conn = get_connection()
        rows = conn.execute(
            """SELECT alert_group, severity, device_ip, device_name,
                      message, details, MAX(timestamp) AS timestamp,
                      COUNT(*) AS count
               FROM alerts
               WHERE severity != 'low' AND alert_group != ''
               GROUP BY alert_group
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
