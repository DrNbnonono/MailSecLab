#!/bin/sh
set -eu
docker exec msl-opendkim mv /usr/share/dns/root.key /usr/share/dns/root.key.bak
docker restart msl-opendkim
sleep 1
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b3
echo '=== domainkey queries'
docker logs --since 1m msl-dns 2>&1 | grep domainkey | tail -10
echo '=== legit dkim line'
docker exec msl-client python3 -c 'import pathlib; t=pathlib.Path("/evidence/w1-20261001a/clients/chain-b3/legit.stored.eml").read_text(errors="replace");
print("\n".join(line for line in t.splitlines()[:14]))'
