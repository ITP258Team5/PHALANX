#!/usr/bin/env python3
"""
Integration tests for v2 schema features:
  1. Migration runs cleanly (v1 → v2)
  2. Triggers fire correctly
  3. Views return data
  4. Access control enforces roles
"""

import os
import sys
import time
import tempfile

sys.path.insert(0, ".")

# Point to a temp DB so we don't clobber anything
tmpdir = tempfile.mkdtemp()
os.environ["PHALANX_BASE"] = tmpdir

import config
config.BASE_DIR = __import__("pathlib").Path(tmpdir)
config.DATA_DIR = config.BASE_DIR / "data"
config.DB_PATH = config.DATA_DIR / "test.db"
config.BLOCKLIST_DIR = config.BASE_DIR / "blocklists"

from core.database import migrate, get_connection, transaction
from core.access_control import (
    create_db_user, RestrictedConnection, bootstrap_default_users
)

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
# 1. Migration
# ══════════════════════════════════════
print("\n── Migration ──")

migrate()
conn = get_connection()

tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
).fetchall()]

test("devices table exists", "devices" in tables)
test("dns_query_log table exists", "dns_query_log" in tables)
test("query_hourly_rollup table exists", "query_hourly_rollup" in tables)
test("query_anomaly_log table exists", "query_anomaly_log" in tables)
test("signon_log table exists", "signon_log" in tables)
test("db_users table exists", "db_users" in tables)

views = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
).fetchall()]

test("v_devices view exists", "v_devices" in views)
test("v_device_block_rate view exists", "v_device_block_rate" in views)
test("v_top_blocked_domains view exists", "v_top_blocked_domains" in views)
test("v_open_anomalies view exists", "v_open_anomalies" in views)

triggers = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name"
).fetchall()]

test("trg_device_last_seen trigger exists", "trg_device_last_seen" in triggers)
test("trg_alert_on_block trigger exists", "trg_alert_on_block" in triggers)
test("trg_dns_hourly_rollup trigger exists", "trg_dns_hourly_rollup" in triggers)
test("trg_anomaly_to_alert trigger exists", "trg_anomaly_to_alert" in triggers)

version = conn.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()
test("Schema version is 2", version and version[0] == "2", f"got: {version}")


# ══════════════════════════════════════
# 2. Trigger: auto-update last_seen
# ══════════════════════════════════════
print("\n── Trigger: device last_seen auto-update ──")

now = time.time()
conn.execute("INSERT INTO devices (ip, name, first_seen, last_seen) VALUES ('10.0.0.1', 'TestPC', ?, 0)", (now,))
conn.commit()

before = conn.execute("SELECT last_seen FROM devices WHERE ip='10.0.0.1'").fetchone()[0]
test("Device last_seen starts at 0", before == 0)

conn.execute("INSERT INTO traffic_log (timestamp, device_ip, domain, blocked) VALUES (?, '10.0.0.1', 'google.com', 0)", (now + 100,))
conn.commit()

after = conn.execute("SELECT last_seen FROM devices WHERE ip='10.0.0.1'").fetchone()[0]
test("Trigger updated last_seen", after == now + 100, f"got: {after}")


# ══════════════════════════════════════
# 3. Trigger: alert on device block
# ══════════════════════════════════════
print("\n── Trigger: alert on device block ──")

alert_count_before = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='device_block'").fetchone()[0]
conn.execute("UPDATE devices SET is_blocked=1 WHERE ip='10.0.0.1'")
conn.commit()

alert_count_after = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='device_block'").fetchone()[0]
test("Blocking device created alert", alert_count_after == alert_count_before + 1)

alert = conn.execute("SELECT severity, message FROM alerts WHERE alert_group='device_block' ORDER BY id DESC LIMIT 1").fetchone()
test("Alert severity is high", alert[0] == "high")
test("Alert mentions device name", "TestPC" in alert[1], f"got: {alert[1]}")


# ══════════════════════════════════════
# 4. Trigger: hourly rollup auto-maintenance
# ══════════════════════════════════════
print("\n── Trigger: hourly rollup ──")

conn.execute("INSERT INTO devices (ip, name) VALUES ('10.0.0.2', 'RollupTest')")
ts = 1700000000.0  # fixed timestamp for predictable bucket
conn.execute(
    "INSERT INTO dns_query_log (timestamp, device_ip, query_name, blocked) VALUES (?, '10.0.0.2', 'example.com', 0)",
    (ts,)
)
conn.execute(
    "INSERT INTO dns_query_log (timestamp, device_ip, query_name, blocked) VALUES (?, '10.0.0.2', 'ads.bad.com', 1)",
    (ts + 30,)
)
conn.execute(
    "INSERT INTO dns_query_log (timestamp, device_ip, query_name, blocked) VALUES (?, '10.0.0.2', 'another.com', 0)",
    (ts + 60,)
)
conn.commit()

rollup = conn.execute(
    "SELECT total_queries, blocked_queries FROM query_hourly_rollup WHERE device_ip='10.0.0.2'"
).fetchone()

test("Rollup counted 3 total queries", rollup and rollup[0] == 3, f"got: {rollup}")
test("Rollup counted 1 blocked query", rollup and rollup[1] == 1)


# ══════════════════════════════════════
# 5. Trigger: anomaly → alert
# ══════════════════════════════════════
print("\n── Trigger: anomaly auto-creates alert ──")

alert_count_before = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='query_anomaly'").fetchone()[0]
conn.execute(
    """INSERT INTO query_anomaly_log
       (detected_at, device_ip, anomaly_type, severity, query_name, observed_value, baseline_value, deviation_sigma, detail)
       VALUES (?, '10.0.0.2', 'volume_spike', 'high', NULL, 450.0, 120.0, 3.8, 'Query rate 3.8σ above baseline')""",
    (now,)
)
conn.commit()

alert_count_after = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='query_anomaly'").fetchone()[0]
test("High anomaly created alert", alert_count_after == alert_count_before + 1)

anomaly = conn.execute("SELECT alert_id FROM query_anomaly_log ORDER BY id DESC LIMIT 1").fetchone()
test("Anomaly back-linked to alert", anomaly[0] is not None, f"alert_id: {anomaly[0]}")

# Low severity should NOT create alert
alert_count_before = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='query_anomaly'").fetchone()[0]
conn.execute(
    """INSERT INTO query_anomaly_log
       (detected_at, device_ip, anomaly_type, severity, detail)
       VALUES (?, '10.0.0.2', 'minor_blip', 'low', 'Nothing serious')""",
    (now,)
)
conn.commit()
alert_count_after = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_group='query_anomaly'").fetchone()[0]
test("Low anomaly did NOT create alert", alert_count_after == alert_count_before)


# ══════════════════════════════════════
# 6. Views
# ══════════════════════════════════════
print("\n── Views ──")

rows = conn.execute("SELECT * FROM v_devices").fetchall()
test("v_devices returns data", len(rows) >= 2)

rows = conn.execute("SELECT * FROM v_open_anomalies").fetchall()
test("v_open_anomalies returns unresolved", len(rows) >= 1)
test("v_open_anomalies sorted by severity", rows[0]["severity"] in ("high", "critical"))


# ══════════════════════════════════════
# 7. Access Control
# ══════════════════════════════════════
print("\n── Access Control ──")

bootstrap_default_users(conn)

# Reader can SELECT views
try:
    with RestrictedConnection(str(config.DB_PATH), "phalanx_reader", "reader_changeme") as rdb:
        rows = rdb.execute("SELECT * FROM v_devices").fetchall()
        test("Reader can SELECT views", len(rows) >= 1)
except Exception as e:
    test("Reader can SELECT views", False, str(e))

# Reader CANNOT insert
try:
    with RestrictedConnection(str(config.DB_PATH), "phalanx_reader", "reader_changeme") as rdb:
        rdb.execute("INSERT INTO traffic_log (timestamp, device_ip, domain, blocked) VALUES (0, 'x', 'y', 0)")
    test("Reader blocked from INSERT", False, "should have raised")
except PermissionError:
    test("Reader blocked from INSERT", True)

# Writer can insert traffic
try:
    with RestrictedConnection(str(config.DB_PATH), "phalanx_writer", "writer_changeme") as wdb:
        wdb.execute("INSERT INTO traffic_log (timestamp, device_ip, domain, blocked) VALUES (?, '10.0.0.1', 'test.com', 0)", (now,))
    test("Writer can INSERT traffic_log", True)
except Exception as e:
    test("Writer can INSERT traffic_log", False, str(e))

# Writer CANNOT drop tables
try:
    with RestrictedConnection(str(config.DB_PATH), "phalanx_writer", "writer_changeme") as wdb:
        wdb.execute("DROP TABLE devices")
    test("Writer blocked from DDL", False, "should have raised")
except PermissionError:
    test("Writer blocked from DDL", True)

# Admin can update subscription_state
try:
    with RestrictedConnection(str(config.DB_PATH), "phalanx_admin", "admin_changeme") as adb:
        adb.execute("UPDATE subscription_state SET value='true' WHERE key='has_subscription'")
    test("Admin can UPDATE subscription_state", True)
except Exception as e:
    test("Admin can UPDATE subscription_state", False, str(e))

# Bad password rejected
try:
    RestrictedConnection(str(config.DB_PATH), "phalanx_admin", "wrongpassword")
    test("Bad password rejected", False, "should have raised")
except PermissionError:
    test("Bad password rejected", True)


# ══════════════════════════════════════
# Seed data from migration
# ══════════════════════════════════════
print("\n── Seed Data ──")

sources = conn.execute("SELECT name FROM blocklist_sources ORDER BY id").fetchall()
test("StevenBlack source seeded", any("StevenBlack" in r[0] for r in sources))
test("Phalanx Curated source seeded", any("Curated" in r[0] for r in sources))

first_signon = conn.execute("SELECT value FROM subscription_state WHERE key='is_first_signon'").fetchone()
test("is_first_signon seeded as true", first_signon and first_signon[0] == "true")


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
