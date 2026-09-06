#!/bin/bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile frspamd --profile mta3b up -d >/dev/null 2>&1; sleep 2
echo "== exim delivery status for retry msgs =="
docker exec exim sh -c 'grep -E "1x3CYG|1x3CZQ|1x3Cd2" /var/log/exim4/main 2>/dev/null | tail -6'
echo "== exim queue =="
docker exec exim exim -bp 2>/dev/null | head -8
echo "== postfix2 recent deliveries =="
docker logs postfix2 2>&1 | grep 'status=' | tail -4
echo "== mailpit: any I1R msgs =="
for c in I1R-exim-to-mailpit-crlf SMUG-I1R-exim-to-mailpit-crlf I1R-postfix1-to-exim-crlf; do
  echo -n "$c: "; docker exec mail-client python3 /scripts/check_delivery.py --case-id $c --timeout 6 2>/dev/null | head -1
done
