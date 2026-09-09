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
log "== K3 matrix: rspamd with working DNS (--dns at creation) =="
docker compose --profile k1 --profile frspamd up -d >/dev/null 2>&1; sleep 2
docker rm -f rs-k3 >/dev/null 2>&1
docker run -d --name rs-k3 --network received-lab_mailnet --dns 172.31.0.53 \
  --add-host maps.rspamd.com:127.0.0.1 \
  -v /mnt/e/MailSecLab/received-lab/results:/results \
  received-lab-rspamd bash -c 'exec rspamd -f -u _rspamd -g _rspamd' >/dev/null
sleep 8
for i in $(seq 1 40); do docker exec rs-k3 sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done
scan() { # case file
    local rj; rj=$(docker exec rs-k3 rspamc --json --ip 192.0.2.200 "$2" 2>/dev/null)
    echo "$rj" > $OUT/${1}.json
    echo "$rj" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    s=d.get('symbols',{})
    dk={k: v.get('options') for k,v in s.items() if 'DKIM' in k}
    print(f\"score={d.get('score')} action={d.get('action')} dkim={dk}\")
except Exception as e: print('SCANFAIL', e)"
}
echo "corpus,scan" > $OUT/k3_rspamd.csv
for pair in "KB1-clean.signed /results/k-series/KB1-clean.signed.eml" \
            "KB3-dup-from /results/k-series/KB3-dupfrom.signed.eml" \
            "KB5-l= /results/k-series/KB5-lplusheaders.signed.eml" \
            "j2_appended-l= /results/j-series/j2_appended.eml" \
            "j1_stored-truncated /results/j-series/j1_stored.eml" \
            "j3_stored-drowned /results/j-series/j3_stored.eml"; do
    set -- $pair
    r=$(scan "$1" "$2")
    echo "$1,$r" >> $OUT/k3_rspamd.csv
    echo "  $1 -> $r" | tee -a $REC
done
docker rm -f rs-k3 >/dev/null 2>&1
log "== K3 MATRIX DONE =="
