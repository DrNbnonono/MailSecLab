#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
log "== G3 v2: WSP normalization scope =="
g3case() { # tag mta server port hdrline case
    local tag=$1 srv=$2 port=$3 line=$4 c=$5
    local r; r=$($MC /scripts/send_g3.py $c $srv $port "$line" 2>&1)
    echo "[$tag $c] $r" | tee -a $REC
    sleep 1
    local chk; chk=$($MC /scripts/check_delivery.py --case-id $c --timeout 8 2>/dev/null | head -1)
    echo "  $chk" | tee -a $REC
    if echo "$chk" | grep -q yes; then
        $MC /scripts/check_delivery.py --dump-case $c > "$OUT/logs/$c.stored.eml" 2>/dev/null
        echo "  input : $(head -2 $OUT/logs/$c.input.eml | tr '\r' '|' | head -c 150)" | tee -a $REC
        echo "  stored: $(head -3 $OUT/logs/$c.stored.eml | tr '\r' '|' | head -c 250)" | tee -a $REC
        echo "  counts: $($MC /scripts/count_received.py /results/g-series/logs/$c.stored.eml 2>/dev/null)" | tee -a $REC
    fi
}
g3case G3A postfix1 25 'Received : from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3A-PF-RCVDWSP
g3case G3B postfix1 25 'Received\t: from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3B-PF-RCVDTAB
g3case G3C postfix1 25 'Subject : wsp subject here' G3C-PF-SUBJWSP
g3case G3D exim 25 'Subject : wsp subject here' G3D-EX-SUBJWSP
g3case G3E exim 25 'Received : from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3E-EX-RCVDWSP
log "== G3 v2 DONE =="
