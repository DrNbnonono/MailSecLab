#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
log "== G1-v2: folding vs line-length vs count =="
echo "mode,kb,file_bytes,score,action,MISSING_FROM" > $OUT/g1_v2.csv
for spec in "f1o 0" "f1t 0" "f1l 0" "f1s 1" "f1s 8"; do
    set -- $spec; mode=$1; kb=$2
    c="G1V2-$mode-$kb"
    gen=$($MC /scripts/gen_g_variant.py /results/g-series/g1 $c $mode $kb)
    bytes=$(echo "$gen" | grep -oP '\s\K\d+(?= bytes)')
    rj=$(docker exec rspamd rspamc --json "/results/g-series/g1/$c.eml" 2>/dev/null)
    echo "$rj" > $OUT/logs/rspamd_$c.json
    line=$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
print(f\"{d.get('score')}|{d.get('action')}|{g('MISSING_FROM')}\")")
    IFS='|' read score action mf <<< "$line"
    echo "$mode,$kb,$bytes,$score,$action,$mf" >> $OUT/g1_v2.csv
    echo "  $mode kb=$kb (${bytes}B): score=$score $action MISSING_FROM=$mf" | tee -a $REC
done
log "== G1-v2 DONE =="
