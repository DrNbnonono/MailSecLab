#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/j-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
log "== J3-final: full chain with persistent mailpit =="
keepup() { docker compose --profile frspamd --profile pf11 up -d >/dev/null 2>&1; }
keepup; sleep 2
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null; sleep 1

$MC /scripts/mk_j3_msg.py /results/j-series/j3_clean.eml clean >/dev/null
$MC /scripts/dkim_sign.py /results/j-series/j3_clean.eml /results/j-series/j3_signed.eml j1 lab.test false from,to,subject,message-id | tee -a $REC
echo -n "1. verify clean: " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_signed.eml 2>/dev/null | tee -a $REC
$MC /scripts/j3_inject.py /results/j-series/j3_signed.eml /results/j-series/j3_injected.eml | tee -a $REC
echo -n "2. verify injected (dkimpy strict parse): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_injected.eml 2>/dev/null | head -1 | tee -a $REC
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/j-series/j3_injected.eml --case-id J3RELAY9 2>&1 | grep DATA_REPLY | tee -a $REC
sleep 2
$MC /scripts/mailpit_dump.py "j3@sender.lab.test" /results/j-series/j3_stored.eml | tee -a $REC
echo "stored first 2 lines:" | tee -a $REC
head -2 $OUT/j3_stored.eml | tr '\r' '|' | tee -a $REC
echo -n "3. verify stored: " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_stored.eml 2>/dev/null | head -1 | tee -a $REC
$MC /scripts/j3_repair.py /results/j-series/j3_stored.eml /results/j-series/j3_repaired.eml | tee -a $REC
echo -n "4. verify repaired: " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_repaired.eml 2>/dev/null | head -1 | tee -a $REC
echo "-- python parser on stored:" | tee -a $REC
$MC /scripts/parse_python.py /results/j-series/j3_stored.eml 2>/dev/null | head -c 280 | tee -a $REC
echo "" | tee -a $REC
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== J3-FINAL DONE =="
