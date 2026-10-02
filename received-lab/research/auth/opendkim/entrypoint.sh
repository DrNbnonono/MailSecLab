#!/bin/sh
set -eu
touch /var/log/unbound.log
chown unbound:unbound /var/log/unbound.log
unbound -c /etc/unbound/unbound.conf
rm -f /tmp/dnsredir-loaded
printf '%s\n' /usr/local/lib/dnsredir.so > /etc/ld.so.preload
/bin/true
wc -l /tmp/dnsredir-loaded > /tmp/entry.log
exec opendkim -f -x /etc/opendkim.conf
