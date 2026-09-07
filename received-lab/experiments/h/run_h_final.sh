#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/h-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
ready() {
  for i in $(seq 1 40); do
    docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
log "== H-final: enable debug logging, scan all, extract ip: per file =="
docker exec rspamd sh -c 'printf "level = \"debug\";\n" > /etc/rspamd/local.d/logging.inc'
docker restart rspamd >/dev/null; sleep 3
ready && log "rspamd up (debug)" || { log "rspamd dead"; exit 1; }

scan() { # container case file -> "score|action"
    local rj; rj=$(docker exec "$1" rspamc --json "$3" 2>/dev/null)
    echo "$rj" > $OUT/${2}.json
    echo "$rj" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(f\"{d.get('score')}|{d.get('action')}\")
except Exception: print('SCANFAIL|')"
}

echo "config,N,src_ip,score,action" > $OUT/h1_matrix.csv
log "== config A (default local_addrs, 172.16/12 trusted) =="
for n in 0 1 5 46 100; do
    r=$(scan rspamd H1-A-N$n /results/h-series/H1-A-N$n.eml)
    sleep 1
    IFS='|' read score action <<< "$r"
    ip=$(docker exec rspamd grep "file: /results/h-series/H1-A-N$n.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1)
    echo "A,$n,${ip:-UNKNOWN},$score,$action" >> $OUT/h1_matrix.csv
    echo "  A N=$n: source_ip=${ip:-UNKNOWN} score=$score $action" | tee -a $REC
done

log "== config B (strict, 172.16/12 removed) via rs-strict =="
docker rm -f rs-strict >/dev/null 2>&1
docker run -d --name rs-strict --network none -v /mnt/e/MailSecLab/received-lab/results:/results received-lab-rspamd \
  bash -c "sed -i 's|^local_addrs = .*|local_addrs = [192.168.0.0/16, 10.0.0.0/8, fd00::/8, 169.254.0.0/16, fe80::/10];|' /etc/rspamd/options.inc && printf 'level = \"debug\";\ntype = \"stderr\";\n' > /etc/rspamd/local.d/logging.inc && exec rspamd -f -u _rspamd -g _rspamd" >/dev/null
sleep 3
for i in $(seq 1 40); do
  docker exec rs-strict sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break
  sleep 2
done
for n in 0 1 5 46 100; do
    r=$(scan rs-strict H1-B-N$n /results/h-series/H1-A-N$n.eml)
    sleep 1
    IFS='|' read score action <<< "$r"
    ip=$(docker logs rs-strict 2>&1 | grep "file: /results/h-series/H1-A-N$n.eml" | grep -oP 'ip: \K[0-9.]+' | tail -1)
    echo "B,$n,${ip:-UNKNOWN},$score,$action" >> $OUT/h1_matrix.csv
    echo "  B N=$n: source_ip=${ip:-UNKNOWN} score=$score $action" | tee -a $REC
done

log "== H3: 9MB true header + relayed forged 46 =="
r=$(scan rspamd H3-F1XF100 /results/f-series/f1/F1-XF100.eml); sleep 1
IFS='|' read score action <<< "$r"
ip=$(docker exec rspamd grep "file: /results/f-series/f1/F1-XF100.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1)
echo "9MB: score=$score action=$action source_ip=${ip:-UNKNOWN}" | tee -a $REC
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null; sleep 1
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/h-series/H3-RELAY46.eml --case-id H3-RELAY46 2>&1 | tail -1 >/dev/null
sleep 3
$MC /scripts/check_delivery.py --dump-case H3-RELAY46 > $OUT/H3-RELAY46.stored.eml 2>/dev/null
echo "stored bytes: $(wc -c < $OUT/H3-RELAY46.stored.eml)" | tee -a $REC
r=$(scan rspamd H3-stored $OUT/H3-RELAY46.stored.eml); sleep 1
IFS='|' read score action <<< "$r"
ip=$(docker exec rspamd grep "file: /results/h-series/H3-RELAY46.stored.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1)
echo "relayed-46 STORED: score=$score action=$action source_ip=${ip:-UNKNOWN}" | tee -a $REC
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== H-FINAL DONE =="
