#!/bin/bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile frspamd up -d >/dev/null 2>&1; sleep 2
MC="docker exec mail-client python3"
REC=results/h-series/../i-series/RECORD.md
OUT=results/j-series
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $OUT/RECORD.md; }
log "== J3-tail: stored-version retrieval by subject + repair + verify =="
docker exec mail-client python3 /scripts/mk_j3_msg.py /results/j-series/j3_clean.eml clean | tee -a $OUT/RECORD.md
head -c 40 $OUT/j3_clean.eml | tr '\r' '|'; echo | tee -a $OUT/RECORD.md
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null; sleep 1
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/j-series/j3_injected.eml --case-id J3RELAY2 2>&1 | grep DATA_REPLY | tee -a $OUT/RECORD.md
sleep 3
$MC /scripts/check_delivery.py --dump-subject "J3 boundary differential" > $OUT/j3_stored.eml 2>/dev/null
echo "stored bytes: $(wc -c < $OUT/j3_stored.eml)" | tee -a $OUT/RECORD.md
head -c 80 $OUT/j3_stored.eml | tr '\r' '|' | head -2 | tee -a $OUT/RECORD.md
echo -n "verify (as stored): " | tee -a $OUT/RECORD.md
$MC /scripts/dkim_verify.py /results/j-series/j3_stored.eml 2>&1 | head -1 | tee -a $OUT/RECORD.md
$MC /scripts/j3_repair.py /results/j-series/j3_stored.eml /results/j-series/j3_repaired.eml | tee -a $OUT/RECORD.md
echo -n "verify (repaired): " | tee -a $OUT/RECORD.md
$MC /scripts/dkim_verify.py /results/j-series/j3_repaired.eml 2>&1 | head -1 | tee -a $OUT/RECORD.md
echo -n "verify (pre-relay injected, for reference): " | tee -a $OUT/RECORD.md
$MC /scripts/dkim_verify.py /results/j-series/j3_injected.eml 2>&1 | head -1 | tee -a $OUT/RECORD.md
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== J3-TAIL DONE =="
