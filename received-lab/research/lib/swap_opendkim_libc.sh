#!/bin/sh
set -eu
docker rm -f msl-opendkim
docker run -d \
  --name msl-opendkim \
  --hostname opendkim.lab.test \
  --network mailseclab-research-net \
  --ip 10.88.0.41 \
  --dns 10.88.0.53 \
  --memory 192m --cpus 0.20 \
  mailseclab-research-opendkim-libc
sleep 1
docker exec msl-opendkim opendkim -V
echo ==== listen
docker exec msl-client python3 -c 'import socket; s=socket.create_connection(("msl-opendkim",8891),3); s.close(); print("8891-open")'
echo ==== send
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b-libc
echo ==== dns
docker logs --since 2m msl-dns 2>&1 | grep domainkey | tail -8
echo ==== dkim
docker exec msl-client python3 -c 'from pathlib import Path
for name in ("legit","from-insert-before"):
    t=Path("/evidence/w1-20261001a/clients/chain-b-libc/"+name+".stored.eml").read_text(errors="replace")
    print("---", name)
    for line in t.splitlines():
        if "dkim=" in line.lower() or "dmarc=" in line.lower():
            print(line)
'
