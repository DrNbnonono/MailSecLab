#!/bin/sh
set -eu
echo '=== resolv'
docker exec msl-opendkim cat /etc/resolv.conf
echo '=== conf'
docker exec msl-opendkim grep -E '^(Mode|AuthservID|Nameservers|Socket)' /etc/opendkim.conf
echo '=== dns log'
docker logs msl-dns 2>&1 | head -20
echo '=== dig'
docker exec msl-dns dig @127.0.0.1 cal._domainkey.lab.test TXT +time=2 +tries=1 +noidentify
echo '=== dig spf'
docker exec msl-dns dig @127.0.0.1 lab.test TXT +short
echo '=== dig dmarc'
docker exec msl-dns dig @127.0.0.1 _dmarc.lab.test TXT +short
