#!/usr/bin/env bash
# =============================================================================
# PHALANX — Weekly Blocklist Updater
# File:    app/scripts/update_blocklist.sh
# Purpose: Download fresh blocklists and reload Phalanx without downtime.
#
# Cron install (run as root):
#   sudo crontab -e
#   Add: 0 3 * * 0  /opt/phalanx/app/scripts/update_blocklist.sh >> /var/log/phalanx/blocklist_update.log 2>&1
#   (Every Sunday at 03:00)
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
PHALANX_DIR="${PHALANX_DIR:-/opt/phalanx}"
LOG_DIR="${LOG_DIR:-/var/log/phalanx}"
BLOCKLIST_DIR="${BLOCKLIST_DIR:-/opt/phalanx/blocklists}"
PHALANX_API="${PHALANX_API:-http://127.0.0.1:80}"
LOG_FILE="${LOG_DIR}/blocklist_update.log"
LOCK_FILE="/tmp/phalanx_blocklist_update.lock"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Subscription-tiered blocklist sources (mirrors app/core/blocklist.py sources)
BLOCKLIST_SOURCES=(
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|stevenblack_hosts.txt|free"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt|hagezi_pro.txt|standard"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt|hagezi_ultimate.txt|premium"
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt|anudeep_ads.txt|free"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[${TIMESTAMP}] $*" | tee -a "$LOG_FILE"; }
log_err() { echo "[${TIMESTAMP}] ERROR: $*" | tee -a "$LOG_FILE" >&2; }

cleanup() {
    rm -f "$LOCK_FILE"
    log "Lock released."
}

# ── Lock (prevent overlapping runs) ──────────────────────────────────────────
if [ -f "$LOCK_FILE" ]; then
    LOCK_PID=$(cat "$LOCK_FILE")
    if kill -0 "$LOCK_PID" 2>/dev/null; then
        log_err "Another update is already running (PID $LOCK_PID). Exiting."
        exit 1
    else
        log "Stale lock found. Removing."
        rm -f "$LOCK_FILE"
    fi
fi
echo $$ > "$LOCK_FILE"
trap cleanup EXIT

# ── Pre-flight checks ─────────────────────────────────────────────────────────
log "======================================================"
log "PHALANX Blocklist Update — Starting"
log "======================================================"

mkdir -p "$LOG_DIR" "$BLOCKLIST_DIR"

if ! command -v curl &>/dev/null; then
    log_err "curl not found. Install with: apt-get install curl"
    exit 1
fi

# ── Download each blocklist ───────────────────────────────────────────────────
TOTAL_DOMAINS=0
UPDATED_COUNT=0
FAILED_COUNT=0

for entry in "${BLOCKLIST_SOURCES[@]}"; do
    IFS="|" read -r url filename tier <<< "$entry"
    dest="${BLOCKLIST_DIR}/${filename}"
    tmp="${dest}.tmp"

    log "Downloading [$tier] $filename ..."

    if curl --silent --fail --max-time 60 --retry 3 --retry-delay 5 \
            --compressed -o "$tmp" "$url"; then

        # Count non-comment, non-empty lines
        domain_count=$(grep -v '^#' "$tmp" | grep -v '^$' | grep -v '^0\.0\.0\.0 0\.0\.0\.0' | wc -l)
        log "  → Downloaded $domain_count entries"

        # Only replace if the new file is non-trivially sized (sanity check)
        if [ "$domain_count" -gt 100 ]; then
            mv "$tmp" "$dest"
            TOTAL_DOMAINS=$((TOTAL_DOMAINS + domain_count))
            UPDATED_COUNT=$((UPDATED_COUNT + 1))
            log "  ✓ $filename updated successfully"
        else
            log_err "  $filename too small ($domain_count lines) — keeping old copy"
            rm -f "$tmp"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        log_err "  Failed to download $url"
        rm -f "$tmp"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

# ── Signal Phalanx to reload blocklists ──────────────────────────────────────
log "Signaling Phalanx to reload blocklists ..."

if curl --silent --fail --max-time 10 \
        -X POST "${PHALANX_API}/api/blocklist/refresh" \
        -H "Content-Type: application/json" &>/dev/null; then
    log "  ✓ Phalanx reloaded blocklists via API"
else
    # Fallback: restart the service if API reload fails
    log "  API reload failed. Attempting service restart ..."
    if systemctl is-active --quiet phalanx; then
        systemctl restart phalanx
        log "  ✓ phalanx.service restarted"
    else
        log_err "  phalanx.service is not running"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log "======================================================"
log "Update complete."
log "  Lists updated : $UPDATED_COUNT"
log "  Lists failed  : $FAILED_COUNT"
log "  Total domains : $TOTAL_DOMAINS"
log "======================================================"

exit 0
