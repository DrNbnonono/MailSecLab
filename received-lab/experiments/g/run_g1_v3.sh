#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
log "== G1-v3: cont-line-count x cont-length matrix =="
echo "conts,contlen,file_bytes,score,action,MISSING_FROM" > $OUT/g1_matrix.csv
for spec in "1 300" "2 300" "1 900" "2 900" "3 900" "5 100" "10 100" "2 100"; do
    set -- $spec; n=$1; len=$2
    c="G1V3-C${n}L${len}"
    gen=$($MC /scripts/gen_g_variant.py /results/g-series/g1 $c f1n $len $n)
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
    echo "$n,$len,$bytes,$score,$action,$mf" >> $OUT/g1_matrix.csv
    echo "  conts=$n len=$len (${bytes}B): score=$score $action MISSING_FROM=$mf" | tee -a $REC
done
log "== G1-v3 DONE =="
