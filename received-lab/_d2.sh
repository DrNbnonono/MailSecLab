#!/bin/bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile frspamd --profile mta3b --profile pf11 up -d >/dev/null 2>&1; sleep 2
echo "== postfix1 statuses =="
docker logs postfix1 2>&1 | grep -E 'AB57D67F|C6AA0BB55|E69F050686' | grep -oP '(?<=postfix/smtp\[(\d+)\]: ).*' | tail -6
echo "== postfix1 queue =="
docker exec postfix1 postqueue -p | head -6
echo "== postfix2n recent =="
docker logs postfix2n 2>&1 | grep 'status=' | tail -3
echo "== exim recent =="
docker exec exim sh -c 'tail -4 /var/log/exim4/main 2>/dev/null'
echo "== direct mailpit search =="
docker exec mail-client python3 /scripts/check_delivery.py --case-id I1-postfix1-to-mailpit-crlf --timeout 8 2>&1 | head -2
