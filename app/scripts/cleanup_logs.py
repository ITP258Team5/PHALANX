#!/usr/bin/env python3
"""
PHALANX — Automated Log & DB Cleanup
File:    app/scripts/cleanup_logs.py
Purpose: Purge log files and old SQLite records older than 30 days.
         Safe to run daily via cron; dry-run mode for testing.

Cron install (run as root):
  sudo crontab -e
  Add: 0 2 * * *  /usr/bin/python3 /opt/phalanx/app/scripts/cleanup_logs.py >> /var/log/phalanx/cleanup.log 2>&1
  (Every day at 02:00)

What it does:
  1. Deletes rotated log FILES older than RETENTION_DAYS from LOG_DIRS.
     (Active logs like dns.log are never deleted — only .log.1, .log.2, etc.)
  2. Purges old ROWS from the SQLite DB tables:
       • dns_queries      — keeps last 30 days
       • alerts           — keeps last 30 days
       • traffic_stats    — keeps last 30 days
       • sign_on_audit    — keeps last 90 days (longer for security audit trail)
  3. Runs VACUUM on the DB to reclaim disk space after large deletions.
  4. Writes a summary to stdout / the cron log.
"""

import argparse
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("phalanx.cleanup")

# ── Defaults ──────────────────────────────────────────────────────────────────
RETENTION_DAYS      = 30
AUDIT_RETENTION_DAYS = 90   # Security audit log kept longer

DEFAULT_DB           = Path("/opt/phalanx/data/phalanx.db")
DEFAULT_LOG_DIRS     = [
    Path("/var/log/phalanx"),
    Path("/opt/phalanx/logs"),
]

# Log file extensions considered "rotated" (safe to delete)
ROTATED_EXTENSIONS = {".1", ".2", ".3", ".4", ".5", ".gz", ".bz2", ".xz", ".old"}

# Table → timestamp column configuration
# Format: (table_name, timestamp_column, retention_days)
DB_TABLE_CONFIG = [
    ("traffic_log",         "timestamp",   RETENTION_DAYS),
    ("dns_query_log",       "timestamp",   RETENTION_DAYS),
    ("alerts",              "timestamp",   RETENTION_DAYS),
    ("query_hourly_rollup", "hour_bucket", RETENTION_DAYS),
    ("query_anomaly_log",   "detected_at", RETENTION_DAYS),
    ("signon_log",          "created_at",  AUDIT_RETENTION_DAYS),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def cutoff_epoch(days: int) -> float:
    """Unix timestamp for `days` ago."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()


# ── File cleanup ──────────────────────────────────────────────────────────────

def cleanup_log_files(
    log_dirs: list[Path],
    retention_days: int,
    dry_run: bool,
) -> dict:
    """
    Walk each directory and delete rotated log files older than retention_days.
    Returns a summary dict.
    """
    cutoff = time.time() - (retention_days * 86400)
    deleted_files = []
    skipped_files = []
    freed_bytes   = 0
    errors        = []

    for directory in log_dirs:
        if not directory.exists():
            log.debug("Log directory not found, skipping: %s", directory)
            continue

        log.info("Scanning: %s", directory)

        for entry in directory.iterdir():
            if not entry.is_file():
                continue

            # Only delete rotated / compressed logs — never the active log
            suffix = entry.suffix.lower()
            is_numbered = any(
                entry.name.endswith(f".log.{n}") for n in range(1, 10)
            )
            is_rotated = suffix in ROTATED_EXTENSIONS or is_numbered

            if not is_rotated:
                skipped_files.append(str(entry))
                log.debug("  Skipping active log: %s", entry.name)
                continue

            try:
                mtime = entry.stat().st_mtime
            except OSError as exc:
                errors.append(f"stat({entry}): {exc}")
                continue

            if mtime >= cutoff:
                log.debug("  Recent, keeping: %s", entry.name)
                continue

            file_size = entry.stat().st_size
            age_days  = (time.time() - mtime) / 86400

            if dry_run:
                log.info("  [DRY-RUN] Would delete: %s (%.0f days old, %s)",
                         entry.name, age_days, human_size(file_size))
                deleted_files.append(str(entry))
                freed_bytes += file_size
            else:
                try:
                    entry.unlink()
                    log.info("  Deleted: %s (%.0f days old, %s)",
                             entry.name, age_days, human_size(file_size))
                    deleted_files.append(str(entry))
                    freed_bytes += file_size
                except OSError as exc:
                    log.error("  Failed to delete %s: %s", entry, exc)
                    errors.append(f"unlink({entry}): {exc}")

    return {
        "deleted":  deleted_files,
        "skipped":  skipped_files,
        "freed":    freed_bytes,
        "errors":   errors,
    }


# ── Database cleanup ──────────────────────────────────────────────────────────

def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def cleanup_db_table(
    conn: sqlite3.Connection,
    table: str,
    ts_col: str,
    retention_days: int,
    dry_run: bool,
) -> int:
    """Delete rows older than retention_days. Returns number of rows affected."""
    if not table_exists(conn, table):
        log.debug("Table '%s' not found — skipping.", table)
        return 0

    cutoff = cutoff_epoch(retention_days)
    count_before = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    if dry_run:
        old_rows = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {ts_col} < ?", (cutoff,)
        ).fetchone()[0]
        log.info("  [DRY-RUN] %s: would delete %d / %d rows (older than %d days)",
                 table, old_rows, count_before, retention_days)
        return old_rows

    conn.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff,))
    conn.commit()
    count_after  = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    deleted      = count_before - count_after
    log.info("  %s: deleted %d rows (kept %d, threshold=%d days)",
             table, deleted, count_after, retention_days)
    return deleted


def vacuum_db(conn: sqlite3.Connection, dry_run: bool) -> None:
    if dry_run:
        log.info("  [DRY-RUN] Would VACUUM database")
        return
    log.info("  Running VACUUM — this may take a moment ...")
    conn.execute("VACUUM")
    log.info("  VACUUM complete")


def cleanup_database(
    db_path: Path,
    dry_run: bool,
) -> dict:
    """Purge old rows from all configured tables, then VACUUM."""
    if not db_path.exists():
        log.warning("Database not found: %s", db_path)
        return {"error": str(db_path), "rows_deleted": 0}

    db_size_before = db_path.stat().st_size
    total_deleted  = 0

    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")

    try:
        for table, ts_col, retention in DB_TABLE_CONFIG:
            deleted = cleanup_db_table(conn, table, ts_col, retention, dry_run)
            total_deleted += deleted

        # Vacuum to shrink the file after deletions
        if total_deleted > 0:
            vacuum_db(conn, dry_run)
    finally:
        conn.close()

    db_size_after  = db_path.stat().st_size if not dry_run else db_size_before
    freed          = db_size_before - db_size_after

    return {
        "rows_deleted":   total_deleted,
        "size_before":    db_size_before,
        "size_after":     db_size_after,
        "freed":          freed,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PHALANX Log & DB Cleanup — purge records older than 30 days"
    )
    parser.add_argument(
        "--db", "-d",
        default=str(DEFAULT_DB),
        help=f"Path to Phalanx SQLite database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--log-dir", "-l",
        action="append",
        dest="log_dirs",
        help="Log directory to scan (may be repeated; default: /var/log/phalanx)",
    )
    parser.add_argument(
        "--retention", "-r",
        type=int,
        default=RETENTION_DAYS,
        help=f"Days to retain logs/records (default: {RETENTION_DAYS})",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be deleted without actually deleting anything",
    )
    parser.add_argument(
        "--skip-files",
        action="store_true",
        help="Skip file deletion (DB cleanup only)",
    )
    parser.add_argument(
        "--skip-db",
        action="store_true",
        help="Skip DB cleanup (file deletion only)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.dry_run:
        log.info("*** DRY-RUN MODE — no files or rows will be deleted ***")

    log_dirs = [Path(d) for d in args.log_dirs] if args.log_dirs else DEFAULT_LOG_DIRS
    db_path  = Path(args.db)

    log.info("=" * 60)
    log.info("PHALANX Cleanup — %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    log.info("Retention: %d days  |  DB: %s", args.retention, db_path)
    log.info("=" * 60)

    # ── 1. Log file cleanup ───────────────────────────────────────────────────
    file_summary = {"deleted": [], "freed": 0, "errors": []}
    if not args.skip_files:
        log.info("[1/2] Cleaning log files ...")
        file_summary = cleanup_log_files(log_dirs, args.retention, args.dry_run)
    else:
        log.info("[1/2] Skipping file cleanup (--skip-files)")

    # ── 2. Database cleanup ───────────────────────────────────────────────────
    db_summary = {"rows_deleted": 0, "freed": 0}
    if not args.skip_db:
        log.info("[2/2] Cleaning database records ...")
        db_summary = cleanup_database(db_path, args.dry_run)
    else:
        log.info("[2/2] Skipping DB cleanup (--skip-db)")

    # ── Summary ───────────────────────────────────────────────────────────────
    total_freed = file_summary["freed"] + db_summary.get("freed", 0)
    log.info("=" * 60)
    log.info("Cleanup complete%s", " (dry-run)" if args.dry_run else "")
    log.info("  Log files deleted : %d", len(file_summary["deleted"]))
    log.info("  File space freed  : %s", human_size(file_summary["freed"]))
    log.info("  DB rows deleted   : %d", db_summary.get("rows_deleted", 0))
    log.info("  DB space freed    : %s", human_size(db_summary.get("freed", 0)))
    log.info("  Total space freed : %s", human_size(total_freed))
    if file_summary["errors"]:
        log.warning("  Errors            : %d", len(file_summary["errors"]))
        for err in file_summary["errors"]:
            log.warning("    %s", err)
    log.info("=" * 60)

    sys.exit(1 if file_summary["errors"] else 0)


if __name__ == "__main__":
    main()
