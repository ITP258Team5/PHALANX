#!/usr/bin/env python3
"""
PHALANX — DNS Engine Log Parser
File:    app/scripts/parse_dns_logs.py
Purpose: Tail or batch-read DNS proxy log output and persist structured
         records to the SQLite database (dns_queries table).

The PHALANX dns_proxy.py already writes query results to SQLite via its
async event loop, but this script provides:
  • Offline / catch-up parsing for log files written during downtime.
  • A structured importer for plain-text or JSON log lines.
  • A --tail mode to follow a live log file like `tail -f`.

Usage:
  # One-shot: parse a rotated log file
  python3 parse_dns_logs.py --logfile /var/log/phalanx/dns.log

  # Tail mode: stream new lines in real time
  python3 parse_dns_logs.py --tail --logfile /var/log/phalanx/dns.log

  # Parse all rotated logs and insert into a specific DB
  python3 parse_dns_logs.py --logfile /var/log/phalanx/dns.log.1 --db /opt/phalanx/data/phalanx.db
"""

import argparse
import json
import logging
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("phalanx.log_parser")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_DB   = Path("/opt/phalanx/data/phalanx.db")
DEFAULT_LOG  = Path("/var/log/phalanx/dns.log")
BATCH_SIZE   = 500          # rows per DB commit
TAIL_INTERVAL = 0.25        # seconds between EOF polls in --tail mode

# ── Regex patterns ────────────────────────────────────────────────────────────
# Matches log lines emitted by dns_proxy.py:
#   [2025-04-15 03:12:44] BLOCKED ads.doubleclick.net A from 192.168.1.42
#   [2025-04-15 03:12:45] ALLOWED google.com A from 192.168.1.10 → 142.250.1.1
#   [2025-04-15 03:12:46] CACHED  github.com AAAA from 192.168.1.10 → 2001:db8::1

LINE_RE = re.compile(
    r"\[(?P<ts>[^\]]+)\]\s+"
    r"(?P<action>BLOCKED|ALLOWED|CACHED|FORWARDED|ERROR)\s+"
    r"(?P<domain>[^\s]+)\s+"
    r"(?P<qtype>[A-Z]+)\s+"
    r"from\s+(?P<client_ip>[\d\.a-fA-F:]+)"
    r"(?:\s+→\s+(?P<response>.+))?$"
)

# JSON log lines (alternate format from structured logging):
#   {"ts": "2025-04-15T03:12:44Z", "action": "BLOCKED", "domain": "...", ...}
def try_parse_json(line: str) -> dict | None:
    """Attempt to parse a JSON-formatted log line."""
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
        # Normalise keys
        return {
            "ts":        obj.get("ts") or obj.get("timestamp") or obj.get("time"),
            "action":    (obj.get("action") or obj.get("verdict") or "UNKNOWN").upper(),
            "domain":    obj.get("domain") or obj.get("name") or "",
            "qtype":     obj.get("qtype") or obj.get("type") or "A",
            "client_ip": obj.get("client_ip") or obj.get("src") or obj.get("client") or "",
            "response":  obj.get("response") or obj.get("answer") or None,
        }
    except (json.JSONDecodeError, AttributeError):
        return None


def parse_timestamp(ts_str: str) -> float:
    """Return a Unix timestamp float from various string formats."""
    if not ts_str:
        return time.time()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return time.time()


def parse_line(line: str) -> dict | None:
    """
    Parse a single log line.  Returns a dict ready for DB insertion, or None.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Try JSON first
    record = try_parse_json(line)
    if record:
        return record

    # Fall back to regex
    m = LINE_RE.match(line)
    if not m:
        return None

    return {
        "ts":        m.group("ts"),
        "action":    m.group("action"),
        "domain":    m.group("domain").rstrip("."),
        "qtype":     m.group("qtype"),
        "client_ip": m.group("client_ip"),
        "response":  m.group("response"),
    }


# ── Database ──────────────────────────────────────────────────────────────────

def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """
    Create the dns_queries table if it does not yet exist.
    This mirrors the schema expected by PHALANX's database.py (v2).
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS dns_query_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,
            device_ip   TEXT    NOT NULL,
            query_name  TEXT    NOT NULL,
            query_type  TEXT    NOT NULL DEFAULT 'A',
            query_class TEXT    NOT NULL DEFAULT 'IN',
            response_code TEXT  NOT NULL DEFAULT 'NOERROR',
            response_ip TEXT,
            blocked     INTEGER NOT NULL DEFAULT 0,
            block_reason TEXT,
            latency_ms  REAL,
            session_id  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_dns_log_timestamp
            ON dns_query_log (timestamp DESC);

        CREATE INDEX IF NOT EXISTS idx_dns_log_device
            ON dns_query_log (device_ip);

        CREATE INDEX IF NOT EXISTS idx_dns_log_query_name
            ON dns_query_log (query_name);

        -- Parsed-log watermark: tracks last byte position per log file
        CREATE TABLE IF NOT EXISTS log_parse_state (
            log_path    TEXT PRIMARY KEY,
            byte_offset INTEGER NOT NULL DEFAULT 0,
            updated_at  REAL    NOT NULL DEFAULT (unixepoch('now'))
        );
    """)
    conn.commit()


def get_offset(conn: sqlite3.Connection, log_path: str) -> int:
    row = conn.execute(
        "SELECT byte_offset FROM log_parse_state WHERE log_path = ?", (log_path,)
    ).fetchone()
    return row[0] if row else 0


def save_offset(conn: sqlite3.Connection, log_path: str, offset: int) -> None:
    conn.execute("""
        INSERT INTO log_parse_state (log_path, byte_offset, updated_at)
        VALUES (?, ?, unixepoch('now'))
        ON CONFLICT(log_path) DO UPDATE SET
            byte_offset = excluded.byte_offset,
            updated_at  = excluded.updated_at
    """, (log_path, offset))
    conn.commit()


def insert_batch(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Bulk-insert a list of parsed records. Returns number inserted."""
    if not rows:
        return 0
    conn.executemany("""
        INSERT INTO dns_query_log (timestamp, device_ip, query_name, query_type, response_ip, blocked, block_reason)
        VALUES (:timestamp, :client_ip, :domain, :qtype, :response, :blocked, :action)
    """, rows)
    conn.commit()
    return len(rows)


# ── Core parsing logic ────────────────────────────────────────────────────────

def process_file(
    log_path: Path,
    conn: sqlite3.Connection,
    resume: bool = True,
    tail: bool = False,
) -> int:
    """
    Read log_path, parse each line, and insert records into the DB.
    If resume=True, continues from the last known byte offset.
    If tail=True, polls the file end for new lines indefinitely.
    Returns total rows inserted this session.
    """
    path_str   = str(log_path.resolve())
    start_off  = get_offset(conn, path_str) if resume else 0
    total_rows = 0
    batch: list[dict] = []

    log.info("Opening %s (offset=%d, tail=%s)", log_path, start_off, tail)

    with open(log_path, "r", errors="replace") as fh:
        fh.seek(start_off)

        while True:
            line = fh.readline()

            if not line:
                # EOF
                if not tail:
                    break
                # In tail mode: flush pending batch, save position, wait
                if batch:
                    total_rows += insert_batch(conn, batch)
                    save_offset(conn, path_str, fh.tell())
                    log.info("Flushed %d rows (total=%d)", len(batch), total_rows)
                    batch.clear()
                time.sleep(TAIL_INTERVAL)
                continue

            record = parse_line(line)
            if record is None:
                continue

            batch.append({
                "timestamp": parse_timestamp(record["ts"]),
                "domain":    record["domain"],
                "qtype":     record["qtype"],
                "client_ip": record["client_ip"],
                "action":    record["action"],
                "response":  record["response"],
                "blocked":   1 if record["action"] == "BLOCKED" else 0,
            })

            if len(batch) >= BATCH_SIZE:
                total_rows += insert_batch(conn, batch)
                save_offset(conn, path_str, fh.tell())
                log.info("Committed batch of %d (total=%d)", BATCH_SIZE, total_rows)
                batch.clear()

        # Flush remaining rows
        if batch:
            total_rows += insert_batch(conn, batch)
            save_offset(conn, path_str, fh.tell())

    log.info("Done. Total rows inserted: %d", total_rows)
    return total_rows


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PHALANX DNS Log Parser — imports dns_proxy log lines into SQLite"
    )
    parser.add_argument(
        "--logfile", "-l",
        default=str(DEFAULT_LOG),
        help=f"Path to the DNS proxy log file (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--db", "-d",
        default=str(DEFAULT_DB),
        help=f"Path to the Phalanx SQLite database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--tail", "-f",
        action="store_true",
        help="Follow the log file continuously (like tail -f)",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Re-read the entire file instead of resuming from last offset",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log_path = Path(args.logfile)
    db_path  = Path(args.db)

    if not log_path.exists():
        log.error("Log file not found: %s", log_path)
        sys.exit(1)
    if not db_path.parent.exists():
        log.error("Database directory does not exist: %s", db_path.parent)
        sys.exit(1)

    conn = get_connection(db_path)
    ensure_schema(conn)

    try:
        process_file(
            log_path=log_path,
            conn=conn,
            resume=not args.no_resume,
            tail=args.tail,
        )
    except KeyboardInterrupt:
        log.info("Interrupted by user — exiting cleanly.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
