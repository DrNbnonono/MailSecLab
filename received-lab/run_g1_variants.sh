#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
log "== G1-variants: isolate the rspamd drop trigger (identity AFTER giant) =="
echo "mode,kb,file_bytes,score,action,MISSING_FROM,RCVD_COUNT_opts" > $OUT/g1_variants.csv
for spec in "f1 1" "f1 2" "f1 4" "f1 6" "f1 8" "f1u 8" "xg 8" "rcv 8" "ctrl 0"; do
    set -- $spec; mode=$1; kb=$2
    c="G1V-$mode-$kb"
    gen=$($MC /scripts/gen_g_variant.py /results/g-series/g1 $c $mode $kb)
    bytes=$(echo "$gen" | grep -oP '\s\K\d+(?= bytes)')
    rj=$(docker exec rspamd rspamc --json "/results/g-series/g1/$c.eml" 2>/dev/null)
    echo "$rj" > $OUT/logs/rspamd_$c.json
    line=$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
rc=s.get('RCVD_COUNT_ZERO',{}).get('options',['-'])[0]
print(f\"{d.get('score')}|{d.get('action')}|{g('MISSING_FROM')}|{rc}\")")
    IFS='|' read score action mf rc <<< "$line"
    echo "$mode,$kb,$bytes,$score,$action,$mf,$rc" >> $OUT/g1_variants.csv
    echo "  $mode kb=$kb (${bytes}B): score=$score $action MISSING_FROM=$mf RCVD0=$rc" | tee -a $REC
done
log "== G1-variants DONE =="
