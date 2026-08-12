#!/bin/bash

# Run as root check
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)."
  exit 1
fi

echo "=== Stopping and disabling tblocker service ==="
systemctl stop tblocker 2>/dev/null || true
systemctl disable tblocker 2>/dev/null || true

echo "=== Removing systemd service file ==="
rm -f /etc/systemd/system/tblocker.service
systemctl daemon-reload

echo "=== Removing application files and configurations ==="
rm -rf /opt/tblocker
rm -f /usr/local/bin/tblock

echo "=== Removing APT repository (if added by install.sh) ==="
rm -f /etc/apt/sources.list.d/openrepo-xray-tools.list
rm -f /usr/share/keyrings/openrepo-xray-tools.gpg
# Uninstall package if it was installed via apt
apt-get remove --purge -y tblocker 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

echo "=== Cleaning up iptables rules (TBLOCKER_BLOCKED) ==="
# Remove jump rule and chain from IPv4 iptables
iptables -t raw -D PREROUTING -j TBLOCKER_BLOCKED 2>/dev/null || true
iptables -t raw -F TBLOCKER_BLOCKED 2>/dev/null || true
iptables -t raw -X TBLOCKER_BLOCKED 2>/dev/null || true

# Remove jump rule and chain from IPv6 ip6tables (for future IPv6 support)
ip6tables -t raw -D PREROUTING -j TBLOCKER_BLOCKED 2>/dev/null || true
ip6tables -t raw -F TBLOCKER_BLOCKED 2>/dev/null || true
ip6tables -t raw -X TBLOCKER_BLOCKED 2>/dev/null || true

echo "=== Cleaning up nftables rules (tblocker table) ==="
nft delete table inet tblocker 2>/dev/null || true

echo "=== Uninstallation Complete! ==="
echo "Your system is clean and ready for a fresh install."
