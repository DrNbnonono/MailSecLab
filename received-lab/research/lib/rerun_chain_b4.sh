#!/bin/sh
set -eu
docker cp /mnt/e/MailSecLab/received-lab/research/auth/opendkim/root.hints msl-opendkim:/usr/share/dns/root.hints
docker exec msl-opendkim sh -c 'printf "nameserver 10.88.0.53\noptions ndots:0\n" > /etc/resolv.conf'
docker restart msl-opendkim
sleep 1
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b4
echo '=== queries from opendkim'
docker logs --since 1m msl-dns 2>&1 | grep '10.88.0.41' | grep -v deb.debian | tail -20
echo '=== header'
docker exec msl-client python3 -c 'import pathlib; t=pathlib.Path("/evidence/w1-20261001a/clients/chain-b4/legit.stored.eml").read_text(errors="replace"); print("\n".join(t.splitlines()[:12]))'
