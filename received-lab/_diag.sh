#!/bin/bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile frspamd up -d >/dev/null 2>&1; sleep 2
echo "== postfix1 relay statuses =="
docker logs postfix1 2>&1 | grep -E 'EAEA7DCC4|D6D1639B2|1CD06DCC8|0FDF935C8|EA2ADDCAE|28BB926968|B112935CB|D0B3B39B2' | grep -oP 'queueid|\bstatus=\S+.*' | tail -8
docker logs postfix1 2>&1 | grep -E 'EAEA7DCC4|D6D1639B2|EA2ADDCAE' | tail -3
echo "== exim mainlog tail =="
docker exec exim sh -c 'tail -6 /var/log/exim4/main 2>/dev/null || tail -6 /var/log/exim4/mainlog 2>/dev/null'
echo "== postfix2n log =="
docker logs postfix2n 2>&1 | grep -E 'status=|reject|warning' | tail -4
echo "== mailpit I1 search =="
docker exec mail-client python3 /scripts/check_delivery.py --case-id I1-postfix1-to-exim-crlf --timeout 5 2>&1 | head -2
