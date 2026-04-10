#!/bin/bash

set -e

echo "=== Phalanx Base Installer ==="

# -----------------------------
# 1. Update system
# -----------------------------
echo "[1/8] Updating system..."
sudo apt update && sudo apt upgrade -y

# -----------------------------
# 2. Create secure admin user
# -----------------------------
echo "[2/8] Creating secure admin user..."

while true; do
    read -p "Enter new admin username (lowercase only): " NEWUSER

    if [[ ! "$NEWUSER" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        echo "❌ Invalid username. Use lowercase letters, numbers, - or _"
        continue
    fi

    if id "$NEWUSER" &>/dev/null; then
        echo "⚠️ User already exists. Choose a different name."
        continue
    fi

    break
done

sudo useradd -m -s /bin/bash "$NEWUSER"
sudo passwd "$NEWUSER"
sudo usermod -aG sudo "$NEWUSER"

echo "✅ User $NEWUSER created."

# -----------------------------
# 3. Remove default pi user
# -----------------------------
echo "[3/8] Removing default pi user..."

if id "pi" &>/dev/null; then
    sudo deluser --remove-home pi || true
    echo "Removed 'pi' user."
else
    echo "'pi' user not found."
fi

# -----------------------------
# 4. Enforce password policy
# -----------------------------
echo "[4/8] Enforcing password policy..."

sudo apt install -y libpam-pwquality

sudo bash -c 'cat > /etc/security/pwquality.conf << EOF
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF'

# Clean and enforce PAM rule
sudo sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
sudo sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 enforce_for_root' /etc/pam.d/common-password

echo "Password policy applied."

# -----------------------------
# 5. Configure static IP
# -----------------------------
echo "[5/8] Configuring static IP..."

CURRENT_IP=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route | grep default | awk '{print $3}')
INTERFACE=$(ip route | grep default | awk '{print $5}')

BASE=$(echo $CURRENT_IP | cut -d. -f1-3)
STATIC_IP="$BASE.50"

echo ""
echo "Detected:"
echo "Interface: $INTERFACE"
echo "Current IP: $CURRENT_IP"
echo "Suggested Static IP: $STATIC_IP"
echo "Gateway: $GATEWAY"
echo ""

read -p "Use suggested static IP? (y/n): " USE_DEFAULT

if [[ "$USE_DEFAULT" != "y" ]]; then
    read -p "Enter static IP: " STATIC_IP
fi

sudo tee -a /etc/dhcpcd.conf > /dev/null <<EOF
interface $INTERFACE
static ip_address=$STATIC_IP/24
static routers=$GATEWAY
static domain_name_servers=1.1.1.1 8.8.8.8
EOF

sudo systemctl restart dhcpcd

# -----------------------------
# 6. Disable unnecessary services
# -----------------------------
echo "[6/8] Disabling unnecessary services..."

sudo systemctl disable bluetooth || true
sudo systemctl stop bluetooth || true

# -----------------------------
# 7. Firewall setup (FIXED)
# -----------------------------
echo "[7/8] Configuring firewall..."

sudo apt install -y ufw

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

SUBNET=$(echo $CURRENT_IP | cut -d. -f1-3).0/24

sudo ufw allow from $SUBNET to any port 22
sudo ufw allow from $SUBNET to any port 53
sudo ufw allow from $SUBNET to any port 80
sudo ufw allow from $SUBNET to any port 443

sudo ufw --force enable

# -----------------------------
# 8. SSH key setup + hardening (FIXED)
# -----------------------------
echo "[8/8] Configuring SSH..."

sudo mkdir -p /home/$NEWUSER/.ssh
sudo chmod 700 /home/$NEWUSER/.ssh

while true; do
    read -p "Paste your PUBLIC SSH key: " PUBKEY

    if [[ -z "$PUBKEY" ]]; then
        echo "❌ Empty key"
        continue
    fi

    if [[ "$PUBKEY" != ssh-rsa* && "$PUBKEY" != ssh-ed25519* ]]; then
        echo "❌ Invalid format (must start with ssh-rsa or ssh-ed25519)"
        continue
    fi

    break
done

echo "$PUBKEY" | sudo tee /home/$NEWUSER/.ssh/authorized_keys > /dev/null

sudo chmod 600 /home/$NEWUSER/.ssh/authorized_keys
sudo chown -R $NEWUSER:$NEWUSER /home/$NEWUSER/.ssh

# Harden SSH
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

sudo systemctl restart ssh

# -----------------------------
# DONE
# -----------------------------
echo ""
echo "=== INSTALL COMPLETE ==="
echo "User: $NEWUSER"
echo "IP Address: $STATIC_IP"
echo ""
echo "SSH:"
echo "ssh $NEWUSER@$STATIC_IP"
echo ""
echo "Web:"
echo "http://$STATIC_IP"
echo ""
echo "Subnet: $SUBNET"
