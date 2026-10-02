#!/bin/sh
set -eu
docker exec msl-opendkim sh -c 'tr "\0" "\n" < /proc/1/environ' | grep LD_PRELOAD || true
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b-fwd
echo ==== dns
docker logs --since 2m msl-dns 2>&1 | grep domainkey | tail -10
echo ==== unbound
docker exec msl-opendkim tail -15 /var/log/unbound.log
echo ==== dkim lines
docker exec msl-client python3 -c 'from pathlib import Path
for name in ("legit","from-insert-before"):
    t=Path("/evidence/w1-20261001a/clients/chain-b-fwd/"+name+".stored.eml").read_text(errors="replace")
    print("---", name)
    for line in t.splitlines():
        if "dkim=" in line.lower() or "dmarc=" in line.lower() or line.lower().startswith("from"):
            print(line)
'
