#!/bin/bash
set -eu
mkdir -p /var/log/exim4 /var/spool/exim4
echo "Exim $(exim --version | head -1)"
exec exim -bdf -C /etc/exim/exim.conf
