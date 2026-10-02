#!/bin/sh
set -eu
docker exec msl-opendkim sed -i 's/^Syslog yes/Syslog no/' /etc/opendkim.conf
docker restart msl-opendkim
sleep 1
docker exec msl-client python3 /opt/research/lib/smtp_send.py \
  --server msl-auth-postfix --port 25 \
  --input /evidence/w1-20261001a/clients/chain-b/legit.eml \
  --transcript /tmp/chain-b-diag.smtp.txt
echo '=== opendkim log'
docker logs --tail 40 msl-opendkim
