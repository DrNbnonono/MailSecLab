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
scan() { # container case file
    local rj; rj=$(docker exec "$1" rspamc --json "$3" 2>/dev/null)
    echo "$rj" > $OUT/${2}.json
    echo "$rj" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    s=d.get('symbols',{})
    src=(s.get('H_SOURCE_IP',{}).get('options') or ['-'])[0]
    syms=';'.join(k for k in s if k!='H_SOURCE_IP')[:220]
    print(f\"{d.get('score')}|{d.get('action')}|{src}|{syms}\")
except Exception: print('SCANFAIL|||')"
}
log "== v4: rspamd stable (network none); plugin debug =="
ensure_rspamd() {
  docker compose --profile frspamd up -d rspamd >/dev/null 2>&1
  ready
}
ensure_rspamd && log "rspamd up" || { log "rspamd dead"; exit 1; }

# plugin: check load error inside container log
docker exec rspamd sh -c 'grep -i "h_ip" /var/log/rspamd/rspamd.log | tail -4' > /tmp/hip_err.txt 2>/dev/null
cat /tmp/hip_err.txt | tee -a $REC
# variant A2: local.d/h_ip.lua WITHOUT the .conf (maybe conf blocks autodiscovery)
docker exec rspamd sh -c 'rm -f /etc/rspamd/local.d/h_ip.conf; cp /usr/share/rspamd/plugins/h_ip.lua /etc/rspamd/local.d/h_ip.lua'
docker restart rspamd >/dev/null; sleep 3; ensure_rspamd
rj=$(docker exec rspamd rspamc --json /results/h-series/H0-PROBE.eml 2>/dev/null)
echo "$rj" | grep -q H_SOURCE_IP && log "variant A2 WORKS" || { log "variant A2 failed; log:"; docker exec rspamd sh -c 'grep -iE "h_ip|plugin" /var/log/rspamd/rspamd.log | tail -4' | tee -a $REC; }
# variant D: config via modules.d symlink layout
if ! echo "$rj" | grep -q H_SOURCE_IP; then
  docker exec rspamd sh -c 'rm -f /etc/rspamd/local.d/h_ip.lua; printf "h_ip {\n  enabled = true;\n}\n" > /etc/rspamd/local.d/h_ip.conf; mkdir -p /usr/share/rspamd/plugins/lua; cp /usr/share/rspamd/plugins/h_ip.lua /usr/share/rspamd/plugins/lua/h_ip.lua'
  docker restart rspamd >/dev/null; sleep 3; ensure_rspamd
  rj=$(docker exec rspamd rspamc --json /results/h-series/H0-PROBE.eml 2>/dev/null)
  echo "$rj" | grep -q H_SOURCE_IP && log "variant D WORKS" || { log "variant D failed; log:"; docker exec rspamd sh -c 'grep -iE "h_ip|plugin" /var/log/rspamd/rspamd.log | tail -4' | tee -a $REC; }
fi
# fallback: debug logs
if ! echo "$rj" | grep -q H_SOURCE_IP; then
  log "all plugin variants failed -> debug-log observable"
  docker exec rspamd sh -c 'printf "level = \"debug\";\n" > /etc/rspamd/local.d/logging.inc'
  docker restart rspamd >/dev/null; sleep 3; ensure_rspamd
  docker exec rspamd rspamc /results/h-series/H0-PROBE.eml >/dev/null 2>&1
  docker exec rspamd sh -c 'grep -E "192\.0\.2|198\.51|203\.0\.113|from_ip|get_from" /var/log/rspamd/rspamd.log | tail -8' | tee -a $REC
fi

log "== H1 matrix rescan =="
echo "config,N,src,score,action,symbols" > $OUT/h1_matrix.csv
for n in 0 1 5 46 100; do
    r=$(scan rspamd H1-A-N$n /results/h-series/H1-A-N$n.eml)
    IFS='|' read score action src syms <<< "$r"
    echo "A,$n,$src,$score,$action,$syms" >> $OUT/h1_matrix.csv
    echo "  A N=$n: $score $action src=$src" | tee -a $REC
done

log "== H2: strict second instance =="
docker rm -f rs-strict >/dev/null 2>&1
docker run -d --name rs-strict --network none -v /mnt/e/MailSecLab/received-lab/results:/results received-lab-rspamd \
  bash -c "sed -i 's|^local_addrs = .*|local_addrs = [192.168.0.0/16, 10.0.0.0/8, fd00::/8, 169.254.0.0/16, fe80::/10];|' /etc/rspamd/options.inc && exec rspamd -f -u _rspamd -g _rspamd" >/dev/null
sleep 3
for i in $(seq 1 40); do
  docker exec rs-strict sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break
  sleep 2
done
docker exec rs-strict grep local_addrs /etc/rspamd/options.inc | head -1 | tee -a $REC
for n in 0 1 5 46 100; do
    r=$(scan rs-strict H1-B-N$n /results/h-series/H1-A-N$n.eml)
    IFS='|' read score action src syms <<< "$r"
    echo "B,$n,$src,$score,$action,$syms" >> $OUT/h1_matrix.csv
    echo "  B N=$n: $score $action src=$src" | tee -a $REC
done

log "== H3: source observable on corrected 9MB + relayed forged =="
r=$(scan rspamd H3-F1XF100 /results/f-series/f1/F1-XF100.eml)
IFS='|' read score action src syms <<< "$r"
echo "9MB true-header: score=$score action=$action src=$src" | tee -a $REC
r=$(scan rspamd H3-stored $OUT/H3-RELAY46.stored.eml)
IFS='|' read score action src syms <<< "$r"
echo "relayed-46 STORED: score=$score action=$action src=$src" | tee -a $REC
log "== v4 DONE =="
