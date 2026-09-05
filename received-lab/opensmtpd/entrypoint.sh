#!/bin/bash
set -e

# OpenSMTPD logs via syslog; run rsyslog in container so evidence is capturable
# from /var/log/syslog.
rm -f /var/run/rsyslogd.pid 2>/dev/null || true
rsyslogd

sleep 1
echo "===================================="
echo "OpenSMTPD starting"
echo "$(/usr/sbin/smtpd -h 2>&1 | head -1)"
echo "===================================="

exec /usr/sbin/smtpd -d -v
