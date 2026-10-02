#!/bin/sh
set -eu
sleep 1
echo ==== entry
docker exec msl-opendkim cat /tmp/entry.log
echo ==== pids
docker exec msl-opendkim cat /tmp/dnsredir-loaded
echo ==== send
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b-fwd3
echo ==== unbound
docker exec msl-opendkim tail -20 /var/log/unbound.log
echo ==== dns
docker logs --since 1m msl-dns 2>&1 | grep domainkey | tail -6
echo ==== lines
docker exec msl-client python3 -c 'from pathlib import Path
for name in ("legit","from-insert-before"):
    t=Path("/evidence/w1-20261001a/clients/chain-b-fwd3/"+name+".stored.eml").read_text(errors="replace")
    print("---", name)
    for line in t.splitlines():
        if "dkim=" in line.lower() or "dmarc=" in line.lower():
            print(line)
'
