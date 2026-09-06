#!/bin/bash
# G-series: characterize rspamd's header-block drop (G1 threshold, G2 drop mode)
# and WSP normalization scope in Postfix/Exim (G3). PRE-RESET at start (lesson).
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/g-series
mkdir -p $OUT/g1 $OUT/logs
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }

cat > $REC <<'HDR'
# G 系列实验记录（2026-09-05）

承接 F1 的两个遗留问题：G1 rspamd 头块丢弃阈值；G2 丢弃模式（字段位置）；
G3 WSP 转正机制范围（Postfix/Exim × Received/Subject × 空格/TAB）。
工具：scripts/gen_g_corpus.py。每组实验开始前显式复位拓扑（F 系列事故教训）。

HDR
log "== PRE-RESET topology =="
docker exec postfix1 postconf -e 'hopcount_limit = 50'; docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix2 postconf -e 'hopcount_limit = 50'; docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'
docker exec postfix3 postconf -e 'hopcount_limit = 50'; docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3; do docker exec $h postfix reload >/dev/null; done
docker exec exim sh -c "sed -i '/^received_headers_max/d; /^header_maxsize/d' /etc/exim/exim.conf"
echo "postfix1: $(docker exec postfix1 postconf hopcount_limit relayhost | tr '\n' ' ')" | tee -a $REC

############################################
log "== G1: rspamd header-block drop threshold (order=from-last) =="
echo "n,kb,approx_hdr_MB,file_bytes,rspamd_ms,score,action,MISSING_FROM,MISSING_TO,MISSING_MID,RCVD_COUNT_opts" > $OUT/g1_threshold.csv
for spec in "5 100" "8 100" "9 100" "10 100" "11 100" "12 100" "15 100" "20 100" "50 100"; do
    set -- $spec; n=$1; kb=$2
    c="G1-N${n}-K${kb}"
    gen=$($MC /scripts/gen_g_corpus.py /results/g-series/g1 $c $n $kb from-last)
    bytes=$(echo "$gen" | grep -oP '\s\K\d+(?= bytes)')
    t0=$(date +%s%N)
    rj=$(docker exec rspamd rspamc --json "/results/g-series/g1/$c.eml" 2>/dev/null)
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    echo "$rj" > $OUT/logs/rspamd_$c.json
    read score action mf mt mm rc <<< "$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
print(d.get('score'), d.get('action'), g('MISSING_FROM'), g('MISSING_TO'), g('MISSING_MID'), s.get('RCVD_COUNT_ZERO',{}).get('options',['-'])[0])")"
    mb=$(python3 -c "print(f'{$bytes/1048576:.2f}')")
    echo "$n,$kb,$mb,$bytes,$ms,$score,$action,$mf,$mt,$mm,$rc" >> $OUT/g1_threshold.csv
    echo "  G1 n=$n kb=$kb (~${mb}MB hdr): ${ms}ms score=$score $action MISSING_FROM=$mf MISSING_TO=$mt MISSING_MID=$mm RCVD0=$rc" | tee -a $REC
done

############################################
log "== G2: drop mode - identity headers BEFORE vs AFTER the giant block =="
echo "case,order,file_bytes,score,action,MISSING_FROM,FROM_HAS_DN,MISSING_SUBJECT,RCVD_COUNT_opts" > $OUT/g2_order.csv
for order in from-last from-first; do
    c="G2-$order"
    $MC /scripts/gen_g_corpus.py /results/g-series/g1 $c 20 100 $order >/dev/null
    rj=$(docker exec rspamd rspamc --json "/results/g-series/g1/$c.eml" 2>/dev/null)
    echo "$rj" > $OUT/logs/rspamd_$c.json
    read score action mf fhd msj rc <<< "$(echo "$rj" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('symbols',{})
g=lambda k: 'Y' if k in s else '-'
print(d.get('score'), d.get('action'), g('MISSING_FROM'), g('FROM_HAS_DN'), g('MISSING_SUBJECT'), s.get('RCVD_COUNT_ZERO',{}).get('options',['-'])[0])")"
    bytes=$(stat -c%s $OUT/g1/$c.eml)
    echo "$order,$bytes,$score,$action,$mf,$fhd,$msj,$rc" >> $OUT/g2_order.csv
    echo "  G2 order=$order: score=$score $action MISSING_FROM=$mf FROM_HAS_DN=$fhd MISSING_SUBJECT=$msj RCVD0=$rc" | tee -a $REC
done
log "G2 note: from-first 若 MISSING_* 消失 -> rspamd 是「读到上限就停止解析头」，不是「丢弃整块」"

############################################
log "== G3: WSP normalization scope (which headers, which whitespace, which MTA) =="
mkmsg() { # case, hdrline
    printf 'X-Case-ID: %s\r\n%s\r\nMessage-ID: <g3@sender.lab.test>\r\n\r\nbody.\r\n' "$1" "$2" > $OUT/logs/$1.input.eml
}
sendfile() { # server port case file -> DATA reply code+text
    docker exec mail-client python3 - "$1" "$2" "$3" "/results/g-series/logs/$3" <<'PYEOF'
import socket,sys
server,port,case,path=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
data=open(path,'rb').read()
s=socket.create_connection((server,port),timeout=30); f=s.makefile("rb")
def rl():
    while True:
        l=f.readline().decode(errors="replace").rstrip()
        if len(l)<4 or l[3]!="-": return l
rl(); s.sendall(b"EHLO client.lab.test\r\n"); rl()
s.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n"); rl()
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); rl()
s.sendall(b"DATA\r\n"); rl()
s.sendall(data+b"\r\n.\r\n")
print("DATA_REPLY:", rl())
PYEOF
}
count_hdr() { # case -> counts via python
    $MC /scripts/check_delivery.py --dump-case "$1" > "$OUT/logs/$1.stored.eml" 2>/dev/null
    echo "input=$(cat $OUT/logs/$1.input.eml | grep -cP '^(Received|Subject)\s*:' 2>/dev/null || true)"
    $MC /scripts/count_received.py "/results/g-series/logs/$1.stored.eml" 2>/dev/null
    echo "-- stored header block (first 12 lines):"
    head -12 "$OUT/logs/$1.stored.eml" | cat -A | head -12
}
g3() { # mta server port hdrname hdrline case
    local tag=$1 srv=$2 port=$3 line=$4 c=$5
    mkmsg $c "$line"
    local r; r=$(sendfile $srv $port $c)
    echo "[$tag/$c] $r" | tee -a $REC
    sleep 1
    count_hdr $c | tee -a $REC
}
echo "" | tee -a $REC
echo "### G3a: Postfix <- 'Received<SP>:' x3" | tee -a $REC
g3 PF postfix1 25 'Received : from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000
Received : from c.lab.test by d.lab.test; Tue, 1 Jan 2030 00:00:00 +0000
Received : from e.lab.test by f.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3A-PF-WSP3
echo "### G3b: Postfix <- 'Received<TAB>:' x3" | tee -a $REC
g3 PF postfix1 25 'Received:	from a.lab.test by b.lab.test; Tue, 1 Jan 2030 00:00:00 +0000
Received:	from c.lab.test by d.lab.test; Tue, 1 Jan 2030 00:00:00 +0000' G3B-PF-TAB2
echo "### G3c: Postfix <- 'Subject<SP>:' x1" | tee -a $REC
g3 PF postfix1 25 'Subject : wsp subject here' G3C-PF-SUBJWSP
echo "### G3d: Exim <- 'Subject<SP>:' x1" | tee -a $REC
g3 EX exim 25 'Subject : wsp subject here' G3D-EX-SUBJWSP
log "== G-SERIES DONE =="
