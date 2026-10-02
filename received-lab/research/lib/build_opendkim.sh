#!/bin/sh
set -eu
python3 -c 'from pathlib import Path
root=Path("/mnt/e/MailSecLab/received-lab/research/auth/opendkim")
for p in root.iterdir():
    if not p.is_file():
        continue
    b=p.read_bytes()
    if b.count(bytes([13])):
        p.write_bytes(b.replace(bytes([13]), b""))
        print("lf", p.name)
    else:
        print("ok", p.name)
'
cd /mnt/e/MailSecLab/received-lab
docker compose -p mailseclab-auth -f research/docker-compose.auth.yml build opendkim
docker compose -p mailseclab-auth -f research/docker-compose.auth.yml up -d opendkim
sleep 1
docker logs --tail 30 msl-opendkim
