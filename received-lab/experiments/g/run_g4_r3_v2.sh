#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
log "== PRE-RESET: standard 3-hop chain =="
docker exec postfix1 postconf -e 'hopcount_limit = 50'; docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix2 postconf -e 'hopcount_limit = 50'; docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'
docker exec postfix3 postconf -e 'hopcount_limit = 50'; docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3; do docker exec $h postfix reload >/dev/null; done

log "== G4-corrected: TRUE folded header block =="
echo "file,bytes,hdr_lines,hdr_bytes,py_ms,py_rc,py_from_present,node_ms,node_from_present,go_ms,go_from_present,rspamd_ms,rspamd_score,rspamd_action,rspamd_MISSING_FROM" > $OUT/g4_corrected.csv
for f in $OUT/f1/F1-XF001.eml $OUT/f1/F1-XF020.eml $OUT/f1/F1-XF100.eml; do
    b=$(basename $f .eml); cf="/results/f-series/f1/$b.eml"
    sz=$(stat -c%s "$f")
    read hl hb <<< "$(python3 -c "
raw=open('$f','rb').read(); i=raw.find(b'\r\n\r\n'); l=raw[:i].split(b'\r\n')
print(len(l), i)")"
    t0=$(date +%s%N); pj=$($MC /scripts/parse_python.py "$cf" 2>/dev/null); pym=$(( ($(date +%s%N)-t0)/1000000 ))
    pfp=$(echo "$pj" | grep -oP '"from_present":\s*\K\w+')
    t0=$(date +%s%N); nj=$(docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "$cf" 2>/dev/null); nom=$(( ($(date +%s%N)-t0)/1000000 ))
    nfp=$(echo "$nj" | grep -oP '"from_present":\K\w+')
    t0=$(date +%s%N); gj=$(docker exec parser-go /usr/local/bin/parse_go "$cf" 2>/dev/null); gom=$(( ($(date +%s%N)-t0)/1000000 ))
    gfp=$(echo "$gj" | grep -oP '"from_present":\K\w+')
    t0=$(date +%s%N); rj=$(docker exec rspamd rspamc --json "$cf" 2>/dev/null); rsm=$(( ($(date +%s%N)-t0)/1000000 ))
    echo "$rj" > $OUT/logs/rspamd_corr_$b.json
    read score action mfr <<< "$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
print(d.get('score'), d.get('action'), g('MISSING_FROM'))")"
    echo "$b,$sz,$hl,$hb,$pym,$pfp,$nom,$nfp,$gom,$gfp,$rsm,$score,$action,$mfr" >> $OUT/g4_corrected.csv
    echo "  $b (${sz}B hdr=$hb): py=${pym}ms from=$pfp | node=${nom}ms from=$nfp | go=${gom}ms from=$gfp | rspamd=${rsm}ms score=$score $action MISSING_FROM=$mfr" | tee -a $REC
done

log "== R3-redo: true header-byte channel =="
echo "n,message_bytes,smtp_reply,check,header_stats,stored_bytes" > $OUT/r3_redo.csv
for n in 50 100; do
    c="R3R-XF$n"
    out=$($MC /scripts/send_folded_xreceived.py $n $c postfix1 2>&1)
    reply=$(echo "$out" | grep -oP 'DATA_REPLY: \K.*' | tail -1)
    bytes=$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+' | tail -1)
    echo "  R3R n=$n send: $reply ($bytes B)" | tee -a $REC
    sleep 3
    chk=$($MC /scripts/check_delivery.py --case-id $c --timeout 15 2>/dev/null | tr '\n' ' ')
    stored=0; stats="-"
    if echo "$chk" | grep -q "DELIVERED: yes"; then
        $MC /scripts/check_delivery.py --dump-case $c > /tmp/r3r_$n.eml 2>/dev/null
        stored=$(wc -c < /tmp/r3r_$n.eml)
        stats=$($MC /scripts/count_received.py /tmp/r3r_$n.eml 2>/dev/null)
    fi
    echo "$n,$bytes,$reply,$chk,$stats,$stored" >> $OUT/r3_redo.csv
    echo "  R3R n=$n: $chk | $stats | stored=$stored" | tee -a $REC
done
log "== G4/R3-REDO v2 DONE =="
