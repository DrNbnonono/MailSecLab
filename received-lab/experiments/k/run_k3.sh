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
log "== K3: rspamd full stack (dnsmasq + maps pinned) =="
docker rm -f rs-canary >/dev/null 2>&1
docker compose --profile k1 --profile frspamd --profile pf11 up -d 2>&1 | tail -1
docker compose --profile frspamd up -d --force-recreate rspamd >/dev/null 2>&1
sleep 3
ok=0
for i in $(seq 1 60); do
  docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
[ $ok = 1 ] && log "rspamd up (networked + dnsmasq)" || { log "rspamd FAILED"; exit 1; }
# sanity: DNS from rspamd container
docker exec rspamd sh -c 'grep -c "nameserver 172.31.0.53" /etc/resolv.conf' >/dev/null && log "rspamd uses dnsmasq" | tee -a $REC
scan() { # case file
    local rj; rj=$(docker exec rspamd rspamc --json "$2" 2>/dev/null)
    echo "$rj" > $OUT/${1}.json
    echo "$rj" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    s=d.get('symbols',{})
    dk=[k for k in s if k.startswith(('R_DKIM','DKIM'))]
    dm=[k for k in s if k.startswith('DMARC')]
    print(f\"score={d.get('score')} action={d.get('action')} dkim={';'.join(dk) or '-'} dmarc={';'.join(dm) or '-'}\")
except Exception as e: print('SCANFAIL', e)"
}
echo "corpus,scan" > $OUT/k3_rspamd.csv
for pair in "KB1-clean.signed /results/k-series/KB1-clean.signed.eml" \
            "KB5-l= /results/k-series/KB5-lplusheaders.signed.eml" \
            "j2_appended-l= /results/j-series/j2_appended.eml" \
            "j1_stored-truncated /results/j-series/j1_stored.eml" \
            "j3_stored-drowned /results/j-series/j3_stored.eml"; do
    set -- $pair
    r=$(scan "$1" "$2")
    echo "$1,$r" >> $OUT/k3_rspamd.csv
    echo "  $1 -> $r" | tee -a $REC
done
log "== K3 DONE =="
