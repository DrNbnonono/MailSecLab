#!/bin/sh
set -eu
cd /mnt/e/MailSecLab/received-lab
docker compose -p mailseclab-auth -f research/docker-compose.auth.yml up -d exim492
sleep 1
docker exec msl-exim492 exim --version | head -2
docker exec msl-client python3 /opt/research/lib/exim492_control.py
echo '=== exim log'
docker logs --tail 40 msl-exim492
