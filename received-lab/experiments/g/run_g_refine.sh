#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }

log "== G1-refine: threshold sweep at small header sizes (order=from-last) =="
echo "n,kb,hdr_bytes,file_bytes,score,action,MISSING_FROM,MISSING_TO,RCVD_COUNT_opts" > $OUT/g1_refine.csv
for spec in "1 8" "1 16" "1 32" "1 48" "1 64" "1 96" "2 32" "2 48" "4 16"; do
    set -- $spec; n=$1; kb=$2
    c="G1R-N${n}-K${kb}"
    gen=$($MC /scripts/gen_g_corpus.py /results/g-series/g1 $c $n $kb from-last)
    bytes=$(echo "$gen" | grep -oP '\s\K\d+(?= bytes)')
    rj=$(docker exec rspamd rspamc --json "/results/g-series/g1/$c.eml" 2>/dev/null)
    echo "$rj" > $OUT/logs/rspamd_$c.json
    line=$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
rc=s.get('RCVD_COUNT_ZERO',{}).get('options',['-'])[0]
print(f\"{d.get('score')}|{d.get('action')}|{g('MISSING_FROM')}|{g('MISSING_TO')}|{rc}\")")
    IFS='|' read score action mf mt rc <<< "$line"
    hdr=$(python3 -c "print($n*$kb*1024)")
    echo "$n,$kb,$hdr,$bytes,$score,$action,$mf,$mt,$rc" >> $OUT/g1_refine.csv
    echo "  n=$n kb=$kb hdr=${hdr}B: score=$score $action MISSING_FROM=$mf MISSING_TO=$mt RCVD0=$rc" | tee -a $REC
done
echo "-- rspamd config knobs mentioning header/size:" | tee -a $REC
docker exec rspamd sh -c "grep -riE 'max.*(hdr|header)|header.*max' /etc/rspamd/ 2>/dev/null | head -5" | tee -a $REC
docker exec rspamd rspamc --help 2>/dev/null | head -1 | tee -a $REC

log "== G3-rewrite: WSP normalization scope (proper CRLF messages) =="
gen_g3() { # case server port body-line
    docker exec mail-client python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import socket, sys
case, server, port, hdrline = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
hdrline = hdrline.replace("\t", "\t")
msg = f"X-Case-ID: {case}\r\n{hdrline}\r\nMessage-ID: <g3@sender.lab.test>\r\n\r\nbody.\r\n".encode()
open(f"/results/g-series/logs/{case}.input.eml","wb").write(msg)
s = socket.create_connection((server, port), timeout=30); f = s.makefile("rb")
def rl():
    while True:
        l = f.readline().decode(errors="replace").rstrip()
        if len(l) < 4 or l[3] != "-": return l
rl(); s.sendall(b"EHLO client.lab.test\r\n"); rl()
s.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n"); rl()
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); rl()
s.sendall(b"DATA\r\n"); rl()
s.sendall(msg + b"\r\n.\r\n")
print("DATA_REPLY:", rl())
s.sendall(b"QUIT\r\n")
PYEOF
}
g3case() { # tag mta server port hdrline case
    local tag=$1 srv=$2 port=$3 line=$4 c=$5
    local r; r=$(gen_g3 $c $srv $port "$line")
    echo "[$tag $c] $r" | tee -a $REC
    sleep 1
    local chk; chk=$($MC /scripts/check_delivery.py --case-id $c --timeout 8 2>/dev/null | head -1)
    echo "  $chk" | tee -a $REC
    if echo "$chk" | grep -q yes; then
        $MC /scripts/check_delivery.py --dump-case $c > "$OUT/logs/$c.stored.eml" 2>/dev/null
        echo "  input header : $(head -c 120 $OUT/logs/$c.input.eml | tr '\r' '|')" | tee -a $REC
        echo "  stored header: $(head -2 $OUT/logs/$c.stored.eml | tr '\r' '|' | head -c 200)" | tee -a $REC
        echo "  stored counts: $($MC /scripts/count_received.py /results/g-series/logs/$c.stored.eml 2>/dev/null)" | tee -a $REC
    fi
}
g3case G3A postfix1 25 'Received : from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3A-PF-RCVDWSP
g3case G3B postfix1 25 'Received\t: from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3B-PF-RCVDTAB
g3case G3C postfix1 25 'Subject : wsp subject here' G3C-PF-SUBJWSP
g3case G3D exim 25 'Subject : wsp subject here' G3D-EX-SUBJWSP
g3case G3E exim 25 'Received : from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3E-EX-RCVDWSP
log "== G-REFINE DONE =="
