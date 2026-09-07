#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/h-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
docker compose --profile frspamd up -d 2>&1 | tail -1
for i in $(seq 1 40); do docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done
docker exec rspamd sh -c 'printf "level = \"debug\";\n" > /etc/rspamd/local.d/logging.inc'
docker restart rspamd >/dev/null; sleep 3
for i in $(seq 1 40); do docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done

log "== H3-tail: relayed forged-46 stored version =="
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null; sleep 1
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/h-series/H3-RELAY46.eml --case-id H3-RELAY46 2>&1 | grep DATA_REPLY | tee -a $REC
sleep 3
$MC /scripts/check_delivery.py --dump-case H3-RELAY46 > $OUT/H3-RELAY46.stored.eml 2>/dev/null
echo "stored bytes: $(wc -c < $OUT/H3-RELAY46.stored.eml)" | tee -a $REC
rj=$(docker exec rspamd rspamc --json /results/h-series/H3-RELAY46.stored.eml 2>/dev/null)
echo "$rj" > $OUT/H3-stored.json
sleep 1
score=$(echo "$rj" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('score'), d.get('action'))")
ip=$(docker exec rspamd grep "file: /results/h-series/H3-RELAY46.stored.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1)
echo "relayed-46 STORED: score=$score source_ip=${ip:-UNKNOWN}" | tee -a $REC

log "== 9MB ip re-extract (longer settle) =="
docker exec rspamd rspamc /results/f-series/f1/F1-XF100.eml >/dev/null 2>&1
sleep 3
ip=$(docker exec rspamd grep "file: /results/f-series/f1/F1-XF100.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1)
echo "9MB(F1-XF100) source_ip=${ip:-UNKNOWN}" | tee -a $REC
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== H3-TAIL DONE =="
