#!/bin/sh
set -eu
docker cp /mnt/e/MailSecLab/received-lab/research/auth/opendkim/opendkim.conf msl-opendkim:/etc/opendkim.conf
docker exec msl-opendkim grep -n -E 'TrustAnchor|Nameservers|AuthservID|Syslog ' /etc/opendkim.conf
docker restart msl-opendkim
sleep 1
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b2
echo '=== dns during send'
docker logs --since 2m msl-dns 2>&1 | grep -E 'domainkey|opendkim|10.88.0.41' | tail -20
