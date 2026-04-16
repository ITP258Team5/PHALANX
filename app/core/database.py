"""
Phalanx Database Schema

Single source of truth for all SQLite tables. Run migrate() on boot
to create or upgrade tables. All other modules import get_connection()
from here instead of managing their own connections.

SQLite is used as an embedded DB on the Pi — no server process, no
network overhead, ~50KB base memory.
"""

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

import config

logger = logging.getLogger("phalanx.db")

_local = threading.local()


SCHEMA_VERSION = 2

MIGRATIONS = {
    1: """
    -- ══════════════════════════════════════════
    -- v1: Initial schema
    -- ══════════════════════════════════════════

    -- Tracks schema version for future migrations
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    -- ── Devices ──
    CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY,
        mac TEXT DEFAULT '',
        name TEXT DEFAULT '',
        device_type TEXT DEFAULT 'unknown',
        first_seen REAL DEFAULT 0,
        last_seen REAL DEFAULT 0,
        is_blocked INTEGER DEFAULT 0
    );

    -- ── Device groups (for alert batching) ──
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        icon TEXT DEFAULT '',
        created_at REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS device_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL REFERENCES devices(ip) ON DELETE CASCADE,
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        UNIQUE(device_ip, group_id)
    );

    -- ── Traffic log ──
    CREATE TABLE IF NOT EXISTS traffic_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        device_ip TEXT NOT NULL REFERENCES devices(ip),
        domain TEXT NOT NULL,
        blocked INTEGER NOT NULL DEFAULT 0,
        block_reason TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_traffic_device ON traffic_log(device_ip);
    CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_traffic_domain ON traffic_log(domain);

    -- ── Device behavioral baselines ──
    CREATE TABLE IF NOT EXISTS device_baselines (
        device_ip TEXT PRIMARY KEY REFERENCES devices(ip) ON DELETE CASCADE,
        avg_queries_per_hour REAL DEFAULT 0,
        std_queries_per_hour REAL DEFAULT 0,
        avg_unique_domains_per_hour REAL DEFAULT 0,
        std_unique_domains_per_hour REAL DEFAULT 0,
        known_domains TEXT DEFAULT '',
        updated_at REAL DEFAULT 0
    );

    -- ── Alerts ──
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
        device_ip TEXT NOT NULL REFERENCES devices(ip),
        device_name TEXT DEFAULT '',
        message TEXT NOT NULL,
        details TEXT DEFAULT '',
        timestamp REAL NOT NULL,
        acknowledged INTEGER DEFAULT 0,
        alert_group TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(alert_group);

    -- ── Blocklist sources (metadata for each list) ──
    CREATE TABLE IF NOT EXISTS blocklist_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        url TEXT DEFAULT '',
        format TEXT DEFAULT 'domains',
        subscription_required INTEGER DEFAULT 0,
        last_updated REAL DEFAULT 0,
        domain_count INTEGER DEFAULT 0,
        file_path TEXT DEFAULT ''
    );

    -- ── Blocklist entries (for "why was this blocked?" lookups) ──
    CREATE TABLE IF NOT EXISTS blocklist_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id INTEGER NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
        domain TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON blocklist_entries(domain);
    CREATE INDEX IF NOT EXISTS idx_blocklist_source ON blocklist_entries(source_id);

    -- ── User overrides (whitelist / blacklist per device or global) ──
    CREATE TABLE IF NOT EXISTS user_overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT DEFAULT '',
        domain TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('whitelist', 'blacklist')),
        created_at REAL DEFAULT 0,
        UNIQUE(device_ip, domain, action)
    );

    -- ── Subscription state (key-value, replaces JSON file) ──
    CREATE TABLE IF NOT EXISTS subscription_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL DEFAULT 0
    );
    """,

    2: """
    -- ══════════════════════════════════════════
    -- v2: Rich query logging, triggers, views,
    --     access control, sign-on audit log
    --     (contributed by teammate)
    -- ══════════════════════════════════════════

    -- ── Detailed DNS query log ──
    -- Richer than traffic_log: captures query type, response code,
    -- latency, resolver used, and which blocklist source blocked it.
    CREATE TABLE IF NOT EXISTS dns_query_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       REAL    NOT NULL DEFAULT 0,
        device_ip       TEXT    NOT NULL REFERENCES devices(ip),
        device_port     INTEGER,
        resolver_ip     TEXT,
        query_name      TEXT    NOT NULL,
        query_type      TEXT    NOT NULL DEFAULT 'A',
        query_class     TEXT    NOT NULL DEFAULT 'IN',
        response_code   TEXT    NOT NULL DEFAULT 'NOERROR',
        response_ip     TEXT,
        response_ttl    INTEGER,
        latency_ms      REAL,
        blocked         INTEGER NOT NULL DEFAULT 0,
        block_reason    TEXT,
        blocklist_source_id INTEGER REFERENCES blocklist_sources(id),
        session_id      TEXT,
        traffic_log_id  INTEGER REFERENCES traffic_log(id)
    );
    CREATE INDEX IF NOT EXISTS idx_dns_device ON dns_query_log(device_ip, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_dns_query_name ON dns_query_log(query_name);
    CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_query_log(blocked, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_dns_session ON dns_query_log(session_id);

    -- ── Pre-aggregated hourly rollup ──
    -- Auto-maintained by trigger. Keeps dashboard queries fast
    -- without scanning millions of raw rows on the Pi.
    CREATE TABLE IF NOT EXISTS query_hourly_rollup (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        hour_bucket     REAL    NOT NULL,
        device_ip       TEXT    NOT NULL REFERENCES devices(ip),
        total_queries   INTEGER NOT NULL DEFAULT 0,
        blocked_queries INTEGER NOT NULL DEFAULT 0,
        unique_domains  INTEGER NOT NULL DEFAULT 0,
        avg_latency_ms  REAL,
        top_domain      TEXT,
        UNIQUE (hour_bucket, device_ip)
    );
    CREATE INDEX IF NOT EXISTS idx_rollup_bucket ON query_hourly_rollup(hour_bucket DESC, device_ip);

    -- ── Structured anomaly log ──
    -- Records anomalies with baseline/observed/sigma for diagnostics.
    CREATE TABLE IF NOT EXISTS query_anomaly_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        detected_at     REAL    NOT NULL DEFAULT 0,
        device_ip       TEXT    NOT NULL REFERENCES devices(ip),
        anomaly_type    TEXT    NOT NULL,
        severity        TEXT    NOT NULL DEFAULT 'low',
        query_name      TEXT,
        observed_value  REAL,
        baseline_value  REAL,
        deviation_sigma REAL,
        detail          TEXT,
        alert_id        INTEGER REFERENCES alerts(id),
        resolved        INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_anomaly_device ON query_anomaly_log(device_ip, detected_at DESC);
    CREATE INDEX IF NOT EXISTS idx_anomaly_severity ON query_anomaly_log(severity, resolved);

    -- ── Sign-on audit log ──
    CREATE TABLE IF NOT EXISTS signon_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        event        TEXT NOT NULL,
        device_ip    TEXT,
        result       TEXT,
        detail       TEXT,
        created_at   REAL DEFAULT 0
    );

    -- ── DB access control users ──
    CREATE TABLE IF NOT EXISTS db_users (
        username      TEXT PRIMARY KEY,
        role          TEXT NOT NULL,
        salt          TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    REAL DEFAULT 0,
        last_login    REAL,
        active        INTEGER DEFAULT 1
    );

    -- ══════════════════════════════════════════
    -- TRIGGERS
    -- ══════════════════════════════════════════

    -- Auto-update device last_seen when traffic is logged
    CREATE TRIGGER IF NOT EXISTS trg_device_last_seen
    AFTER INSERT ON traffic_log
    BEGIN
        UPDATE devices SET last_seen = NEW.timestamp WHERE ip = NEW.device_ip;
    END;

    -- Auto-create alert when a device is blocked
    CREATE TRIGGER IF NOT EXISTS trg_alert_on_block
    AFTER UPDATE OF is_blocked ON devices
    WHEN NEW.is_blocked = 1
    BEGIN
        INSERT INTO alerts (severity, device_ip, device_name, message, timestamp, alert_group)
        SELECT 'high', NEW.ip, NEW.name,
               'Device ' || COALESCE(NEW.name, NEW.ip) || ' has been blocked.',
               CAST(strftime('%s','now') AS REAL),
               'device_block';
    END;

    -- Auto-maintain hourly rollup on DNS query insert
    CREATE TRIGGER IF NOT EXISTS trg_dns_hourly_rollup
    AFTER INSERT ON dns_query_log
    BEGIN
        INSERT INTO query_hourly_rollup (hour_bucket, device_ip, total_queries, blocked_queries)
        VALUES (
            (CAST(NEW.timestamp / 3600 AS INTEGER)) * 3600,
            NEW.device_ip, 1, NEW.blocked
        )
        ON CONFLICT(hour_bucket, device_ip) DO UPDATE SET
            total_queries   = total_queries + 1,
            blocked_queries = blocked_queries + NEW.blocked;
    END;

    -- Auto-create alert from high/critical anomalies
    CREATE TRIGGER IF NOT EXISTS trg_anomaly_to_alert
    AFTER INSERT ON query_anomaly_log
    WHEN NEW.severity IN ('high', 'critical')
    BEGIN
        INSERT INTO alerts (severity, device_ip, message, details, timestamp, alert_group)
        VALUES (
            NEW.severity,
            NEW.device_ip,
            'Query anomaly: ' || NEW.anomaly_type || ' on ' || COALESCE(NEW.query_name, 'unknown'),
            'Observed: ' || COALESCE(NEW.observed_value, 0) ||
            ' | Baseline: ' || COALESCE(NEW.baseline_value, 0) ||
            ' | Sigma: ' || COALESCE(NEW.deviation_sigma, 0),
            NEW.detected_at,
            'query_anomaly'
        );
        UPDATE query_anomaly_log SET alert_id = last_insert_rowid() WHERE id = NEW.id;
    END;

    -- Log sign-in events
    CREATE TRIGGER IF NOT EXISTS trg_log_signin
    AFTER UPDATE OF value ON subscription_state
    WHEN NEW.key = 'user_signed_in' AND NEW.value = 'true'
    BEGIN
        INSERT INTO signon_log (event, result, detail, created_at)
        VALUES ('user_signin', 'pass', 'User authenticated.', CAST(strftime('%s','now') AS REAL));
    END;

    -- ══════════════════════════════════════════
    -- READ-ONLY VIEWS (for least-privilege access)
    -- ══════════════════════════════════════════

    CREATE VIEW IF NOT EXISTS v_devices AS
        SELECT ip, mac, name, device_type, first_seen, last_seen, is_blocked
        FROM devices;

    CREATE VIEW IF NOT EXISTS v_traffic_log AS
        SELECT id, timestamp, device_ip, domain, blocked, block_reason
        FROM traffic_log;

    CREATE VIEW IF NOT EXISTS v_alerts AS
        SELECT id, severity, device_ip, device_name, message, timestamp, acknowledged
        FROM alerts;

    CREATE VIEW IF NOT EXISTS v_blocklist_entries AS
        SELECT be.id, bs.name AS source_name, be.domain
        FROM blocklist_entries be
        JOIN blocklist_sources bs ON bs.id = be.source_id;

    -- Per-device block rate (last 24h)
    CREATE VIEW IF NOT EXISTS v_device_block_rate AS
        SELECT
            device_ip,
            COUNT(*)                                    AS total_queries,
            SUM(blocked)                                AS blocked_queries,
            ROUND(100.0 * SUM(blocked) / COUNT(*), 2)  AS block_rate_pct,
            COUNT(DISTINCT query_name)                  AS unique_domains
        FROM dns_query_log
        WHERE timestamp >= CAST(strftime('%s','now') AS REAL) - 86400
        GROUP BY device_ip;

    -- Top blocked domains (last 24h)
    CREATE VIEW IF NOT EXISTS v_top_blocked_domains AS
        SELECT
            query_name          AS domain,
            COUNT(*)            AS block_count,
            COUNT(DISTINCT device_ip) AS device_count,
            MAX(timestamp)      AS last_seen,
            block_reason
        FROM dns_query_log
        WHERE blocked = 1
          AND timestamp >= CAST(strftime('%s','now') AS REAL) - 86400
        GROUP BY query_name, block_reason
        ORDER BY block_count DESC;

    -- Open anomalies
    CREATE VIEW IF NOT EXISTS v_open_anomalies AS
        SELECT
            a.id, a.detected_at, a.device_ip,
            d.name AS device_name,
            a.anomaly_type, a.severity, a.query_name,
            a.observed_value, a.baseline_value, a.deviation_sigma,
            a.detail
        FROM query_anomaly_log a
        LEFT JOIN devices d ON d.ip = a.device_ip
        WHERE a.resolved = 0
        ORDER BY
            CASE a.severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 ELSE 4
            END,
            a.detected_at DESC;

    -- ══════════════════════════════════════════
    -- SEED DATA
    -- ══════════════════════════════════════════

    INSERT OR IGNORE INTO subscription_state (key, value) VALUES
        ('is_first_signon',      'true'),
        ('user_signed_in',       'false'),
        ('blocklist_initialized','false');

    INSERT OR IGNORE INTO blocklist_sources (name, url, format, subscription_required, domain_count)
    VALUES
        ('StevenBlack Unified', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'hosts', 0, 0),
        ('anudeepND Ads', 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt', 'domains', 0, 0),
        ('Hagezi Pro', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt', 'domains', 1, 0),
        ('Hagezi Ultimate', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt', 'domains', 1, 0),
        ('Phalanx Curated', '', 'domains', 1, 0);
    """,
}


def get_connection(db_path: Path = None) -> sqlite3.Connection:
    """
    Get a thread-local SQLite connection. Reuses the same connection
    within a thread to avoid overhead.
    """
    db_path = db_path or config.DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
            timeout=10,
        )
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn.execute("PRAGMA busy_timeout=5000")
        _local.conn.row_factory = sqlite3.Row

    return _local.conn


@contextmanager
def transaction(conn: sqlite3.Connection = None):
    """Context manager for atomic transactions."""
    conn = conn or get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def get_current_version(conn: sqlite3.Connection) -> int:
    """Get the current schema version from the database."""
    try:
        cursor = conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        )
        row = cursor.fetchone()
        return int(row["value"]) if row else 0
    except sqlite3.OperationalError:
        return 0


def migrate(db_path: Path = None):
    """
    Run all pending migrations. Safe to call on every boot —
    skips already-applied versions.
    """
    conn = get_connection(db_path)
    current = get_current_version(conn)

    if current >= SCHEMA_VERSION:
        logger.info("Database schema is up to date (v%d)", current)
        return

    for version in range(current + 1, SCHEMA_VERSION + 1):
        sql = MIGRATIONS.get(version)
        if sql is None:
            raise RuntimeError(f"Missing migration for version {version}")

        logger.info("Applying migration v%d...", version)
        conn.executescript(sql)
        conn.execute(
            """INSERT INTO schema_meta (key, value)
               VALUES ('version', ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (str(version),),
        )
        conn.commit()
        logger.info("Migration v%d applied successfully", version)

    logger.info("Database migrated to v%d", SCHEMA_VERSION)


def close():
    """Close the thread-local connection."""
    if hasattr(_local, "conn") and _local.conn:
        _local.conn.close()
        _local.conn = None
