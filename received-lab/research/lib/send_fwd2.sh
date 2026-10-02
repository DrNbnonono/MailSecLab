#!/bin/sh
set -eu
sleep 1
echo ==== loaded
docker exec msl-opendkim cat /tmp/dnsredir-loaded || echo missing
docker exec msl-opendkim cat /etc/ld.so.preload
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b-fwd2
echo ==== unbound
docker exec msl-opendkim tail -30 /var/log/unbound.log
echo ==== dns
docker logs --since 1m msl-dns 2>&1 | grep domainkey | tail -8
echo ==== lines
docker exec msl-client python3 -c 'from pathlib import Path
for name in ("legit","from-insert-before"):
    t=Path("/evidence/w1-20261001a/clients/chain-b-fwd2/"+name+".stored.eml").read_text(errors="replace")
    print("---", name)
    for line in t.splitlines():
        low=line.lower()
        if "dkim=" in low or "dmarc=" in low:
            print(line)
'
