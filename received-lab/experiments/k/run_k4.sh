#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/k-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
keepup() { docker compose --profile k1 --profile frspamd --profile pf11 up -d >/dev/null 2>&1; }
log "== K4: matrix completion =="
keepup; sleep 2
# rspamd instance with working DNS (docker-run pattern from K3 matrix)
docker rm -f rs-k3 >/dev/null 2>&1
docker run -d --name rs-k3 --network received-lab_mailnet --dns 172.31.0.53 \
  --add-host maps.rspamd.com:127.0.0.1 \
  -v /mnt/e/MailSecLab/received-lab/results:/results \
  received-lab-rspamd bash -c 'exec rspamd -f -u _rspamd -g _rspamd' >/dev/null
sleep 8
for i in $(seq 1 40); do docker exec rs-k3 sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done

log "== K4a: KB2-anomaly (valid signature + forged Received) on rspamd =="
rj=$(docker exec rs-k3 rspamc --json --ip 192.0.2.200 /results/k-series/KB2-anomaly.signed.eml 2>/dev/null)
echo "$rj" > $OUT/KB2-anomaly.rspamd.json
echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
dk={k: v.get('options') for k,v in s.items() if 'DKIM' in k}
print('score', d.get('score'), '| action', d.get('action'), '| dkim', dk)" | tee -a $REC

log "== K4b: KB3-reverse (first=mallory second=alice) selection probe =="
$MC /scripts/mk_kb3rev.py /results/k-series/KB3-rev.eml | tee -a $REC
$MC /scripts/dkim_sign.py /results/k-series/KB3-rev.eml /results/k-series/KB3-rev.signed.eml j1 lab.test false | tail -1 | tee -a $REC
echo "-- dkimpy:"; $MC /scripts/dkim_verify.py /results/k-series/KB3-rev.signed.eml 2>/dev/null | tee -a $REC
echo "-- perl:"; docker exec perl-mail-dkim sh -c "verify.pl < /results/k-series/KB3-rev.signed.eml" 2>&1 | tee -a $REC
echo "-- go:"; docker exec go-msgauth sh -c "dkim-verify < /results/k-series/KB3-rev.signed.eml" 2>&1 | tee -a $REC
echo "-- rspamd:"; rj=$(docker exec rs-k3 rspamc --json --ip 192.0.2.200 /results/k-series/KB3-rev.signed.eml 2>/dev/null)
echo "$rj" > $OUT/KB3-rev.rspamd.json
echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
dk={k: v.get('options') for k,v in s.items() if 'DKIM' in k}
print('score', d.get('score'), '| dkim', dk)" | tee -a $REC
docker rm -f rs-k3 >/dev/null 2>&1
log "== K4 DONE =="
