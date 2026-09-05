#!/bin/bash
set -e

mkdir -p /var/log/exim4 /var/spool/exim4 /var/run/exim4
chown -R Debian-exim:Debian-exim /var/log/exim4 /var/spool/exim4 2>/dev/null || true

echo "===================================="
echo "Exim starting"
echo "$(/usr/sbin/exim --version 2>&1 | head -1)"
echo "===================================="

exec /usr/sbin/exim -bdf -C /etc/exim/exim.conf
