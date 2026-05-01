#!/usr/bin/env bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════
# Phalanx SSH Port Swap
#
# Moves real SSH from port 22 → port 2222 so the honeypot
# can listen on port 22 (where real attackers scan).
#
# SAFETY: This script verifies SSH is working on the new port
# BEFORE closing the old one. If anything fails, it reverts.
#
# After running this, connect to the Pi via:
#   ssh <user>@<ip> -p 2222
# ══════════════════════════════════════════════════════════════

echo ""
echo "========================================"
echo "  Phalanx SSH Port Swap"
echo "========================================"
echo ""
echo "  This will:"
echo "    1. Move real SSH from port 22 → port 2222"
echo "    2. Free port 22 for the honeypot"
echo "    3. Update firewall rules"
echo ""
echo "  After this, connect to the Pi with:"
echo "    ssh <user>@<ip> -p 2222"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: Run as root (sudo bash $0)"
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
NEW_PORT=2222
OLD_PORT=22

# ── Safety: back up sshd_config ──
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.phalanx"
echo "[1/5] Backed up sshd_config"

# ── Rollback function ──
rollback() {
    echo ""
    echo "⚠️  Something went wrong. Reverting..."
    cp "${SSHD_CONFIG}.bak.phalanx" "$SSHD_CONFIG"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    echo "  SSH restored to port $OLD_PORT"
    exit 1
}
trap rollback ERR

# ── Step 1: Add port 2222 ALONGSIDE port 22 (both listen temporarily) ──
echo "[2/5] Adding port $NEW_PORT to SSH (keeping port $OLD_PORT active)..."

# Remove any existing Port lines and add both
sed -i '/^#*Port /d' "$SSHD_CONFIG"
sed -i "1i Port $OLD_PORT" "$SSHD_CONFIG"
sed -i "2i Port $NEW_PORT" "$SSHD_CONFIG"

# Restart SSH with both ports
if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
    echo "       SSH now listening on BOTH ports $OLD_PORT and $NEW_PORT"
else
    echo "       ❌ SSH restart failed"
    rollback
fi

# ── Step 2: Verify new port works ──
echo "[3/5] Verifying SSH on port $NEW_PORT..."
sleep 2

if ss -tlnp | grep -q ":${NEW_PORT}"; then
    echo "       ✅ Port $NEW_PORT is listening"
else
    echo "       ❌ Port $NEW_PORT not listening"
    rollback
fi

# ── Step 3: Remove old port (now only 2222) ──
echo "[4/5] Removing port $OLD_PORT from SSH..."

sed -i '/^Port '"$OLD_PORT"'$/d' "$SSHD_CONFIG"

if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
    echo "       SSH now on port $NEW_PORT only"
else
    echo "       ❌ SSH restart failed"
    rollback
fi

# Verify old port is free
sleep 2
if ss -tlnp | grep -q ":${OLD_PORT}"; then
    echo "       ⚠️  Port $OLD_PORT still in use — may need a moment"
else
    echo "       ✅ Port $OLD_PORT is free for honeypot"
fi

# ── Step 4: Update firewall ──
echo "[5/5] Updating firewall..."
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    SUBNET=$(hostname -I | awk '{print $1}' | cut -d. -f1-3).0/24

    # Allow new SSH port
    ufw allow from "$SUBNET" to any port $NEW_PORT 2>/dev/null || true

    # Allow honeypot ports from anywhere (that's the point)
    ufw allow 22/tcp 2>/dev/null || true
    ufw allow 23/tcp 2>/dev/null || true
    ufw allow 21/tcp 2>/dev/null || true

    echo "       Firewall updated"
else
    echo "       UFW not active"
fi

echo ""
echo "========================================"
echo "  ✅ SSH Port Swap Complete"
echo ""
echo "  Real SSH:    port $NEW_PORT (your admin access)"
echo "  Honeypot:    port $OLD_PORT (trap for attackers)"
echo ""
echo "  Connect with:"
echo "    ssh $(whoami)@$(hostname -I | awk '{print $1}') -p $NEW_PORT"
echo ""
echo "  Restart Phalanx to activate honeypot on port 22:"
echo "    sudo systemctl restart phalanx"
echo "========================================"
