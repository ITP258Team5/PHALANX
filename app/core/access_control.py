"""
Phalanx Database Access Control

Least-privilege access for SQLite. Since SQLite has no native user
accounts, we enforce roles at the Python layer:

  app_reader  → SELECT on read-only views only
  app_writer  → INSERT traffic/alerts, UPDATE device state
  app_admin   → Full DML access

Adapted from teammate's db_access_control.py.
"""

import hashlib
import logging
import os
import sqlite3
from pathlib import Path

import config

logger = logging.getLogger("phalanx.access")

ROLE_PERMISSIONS = {
    "app_reader": {
        "SELECT": [
            "v_traffic_log", "v_alerts", "v_devices", "v_blocklist_entries",
            "v_device_block_rate", "v_top_blocked_domains", "v_open_anomalies",
            "blocklist_sources", "groups", "device_groups", "device_baselines",
            "query_hourly_rollup",
        ],
        "INSERT": [],
        "UPDATE": [],
        "DELETE": [],
    },
    "app_writer": {
        "SELECT": [
            "v_traffic_log", "v_alerts", "v_devices", "v_blocklist_entries",
            "v_device_block_rate", "v_top_blocked_domains", "v_open_anomalies",
            "blocklist_sources", "groups", "device_groups", "device_baselines",
            "signon_log", "query_hourly_rollup", "dns_query_log",
        ],
        "INSERT": [
            "traffic_log", "dns_query_log", "alerts", "signon_log",
            "device_baselines", "device_groups", "query_anomaly_log",
        ],
        "UPDATE": ["devices"],
        "DELETE": [],
    },
    "app_admin": {
        "SELECT": ["__ALL__"],
        "INSERT": [
            "traffic_log", "dns_query_log", "alerts", "signon_log",
            "device_baselines", "device_groups", "user_overrides",
            "blocklist_entries", "query_anomaly_log",
        ],
        "UPDATE": [
            "devices", "subscription_state", "user_overrides",
            "blocklist_sources", "query_anomaly_log",
        ],
        "DELETE": ["user_overrides", "alerts", "traffic_log", "dns_query_log"],
    },
}


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


def create_db_user(conn: sqlite3.Connection, username: str, password: str, role: str):
    """Create or replace a DB access user."""
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"Unknown role '{role}'. Valid: {list(ROLE_PERMISSIONS)}")
    salt = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    pw_hash = _hash_password(password, salt)
    conn.execute(
        "INSERT OR REPLACE INTO db_users (username, role, salt, password_hash, created_at) VALUES (?,?,?,?,CAST(strftime('%s','now') AS REAL))",
        (username, role, salt, pw_hash),
    )
    conn.commit()
    logger.info("DB user '%s' created with role '%s'", username, role)


class RestrictedConnection:
    """
    Wraps sqlite3.Connection and enforces role-based access at the
    SQL statement level before any query reaches the engine.
    """

    def __init__(self, db_path: str, username: str, password: str):
        _auth_conn = sqlite3.connect(db_path)
        row = _auth_conn.execute(
            "SELECT role, salt, password_hash, active FROM db_users WHERE username=?",
            (username,),
        ).fetchone()
        _auth_conn.close()

        if not row:
            raise PermissionError(f"User '{username}' does not exist.")
        role, salt, pw_hash, active = row
        if not active:
            raise PermissionError(f"User '{username}' is disabled.")
        if _hash_password(password, salt) != pw_hash:
            raise PermissionError("Invalid password.")

        self.username = username
        self.role = role
        self.permissions = ROLE_PERMISSIONS[role]
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row

        if role == "app_reader":
            self._conn.execute("PRAGMA query_only = ON")

        # Stamp last_login
        _stamp = sqlite3.connect(db_path)
        _stamp.execute(
            "UPDATE db_users SET last_login=CAST(strftime('%s','now') AS REAL) WHERE username=?",
            (username,),
        )
        _stamp.commit()
        _stamp.close()

    def _check_permission(self, sql: str):
        sql_stripped = sql.strip().upper()
        verb = sql_stripped.split()[0]

        if verb not in ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH"):
            raise PermissionError(
                f"[{self.role}] DDL/admin statements not permitted. Blocked: {verb}"
            )

        allowed_tables = self.permissions.get(verb, [])
        if verb == "WITH":
            allowed_tables = self.permissions.get("SELECT", [])

        if "__ALL__" in allowed_tables:
            return

        tokens = sql_stripped.split()
        table = None
        try:
            if verb in ("SELECT", "WITH"):
                idx = tokens.index("FROM") if "FROM" in tokens else -1
                table = tokens[idx + 1].strip("();,").lower() if idx >= 0 else None
            elif verb == "INSERT":
                idx = tokens.index("INTO") if "INTO" in tokens else 1
                table = tokens[idx + 1].strip("();,").lower()
            elif verb in ("UPDATE", "DELETE"):
                t_idx = 2 if verb == "DELETE" else 1
                table = tokens[t_idx].strip("();,").lower()
        except IndexError:
            pass

        if table and table not in [t.lower() for t in allowed_tables]:
            raise PermissionError(
                f"[{self.role}] '{verb}' on '{table}' not permitted. "
                f"Allowed: {allowed_tables}"
            )

    def execute(self, sql: str, params=()):
        self._check_permission(sql)
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, params):
        self._check_permission(sql)
        return self._conn.executemany(sql, params)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._conn.commit()
        self._conn.close()


def get_restricted_connection(username: str, password: str) -> RestrictedConnection:
    """Get a role-restricted DB connection. Use this from API endpoints."""
    return RestrictedConnection(str(config.DB_PATH), username, password)


def bootstrap_default_users(conn: sqlite3.Connection):
    """Create default DB users on first boot. Passwords should be overridden via env vars."""
    users = [
        ("phalanx_reader", os.environ.get("PHALANX_DB_READER_PASS", "reader_changeme"), "app_reader"),
        ("phalanx_writer", os.environ.get("PHALANX_DB_WRITER_PASS", "writer_changeme"), "app_writer"),
        ("phalanx_admin", os.environ.get("PHALANX_DB_ADMIN_PASS", "admin_changeme"), "app_admin"),
    ]
    for username, password, role in users:
        try:
            create_db_user(conn, username, password, role)
        except Exception as e:
            logger.debug("User '%s' may already exist: %s", username, e)
