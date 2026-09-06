#!/bin/bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile frspamd up -d 2>&1 | tail -1
sleep 3
for m in postfix1 exim opensmtpd postfix1n mailpit; do
  echo "== $m =="
  docker exec mail-client python3 /scripts/probe_ehlo.py $m 25 2>&1 | grep -iE 'chunk|pipelin|250' | head -3
done
