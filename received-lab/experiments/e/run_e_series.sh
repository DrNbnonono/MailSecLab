#!/bin/bash
# E-series: map the real bound surface of Received-header growth.
# E1 count ceiling per MTA, E2 byte ceiling, E3 blind-spot matrix (+parsers),
# E4 heterogeneous chain growth, E5 amplification (big headers x loop).
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/e-series
mkdir -p "$OUT/e3raw"
MC="docker exec mail-client python3"

log() { echo "[$(date +%H:%M:%S)] $*"; }

send() { # server port caseid extra-args... -> prints "code bytes"
    local s=$1 p=$2 c=$3; shift 3
    local out code
    out=$($MC /scripts/send_received.py --server "$s" --port "$p" --case-id "$c" "$@" 2>/dev/null)
    code=$(echo "$out" | grep -oP 'DATA_REPLY: \K\d{3}' | tail -1)
    local bytes; bytes=$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+' | tail -1)
    echo "${code:-ERR} ${bytes:-0}"
}

check() { # caseid -> "delivered received_count bounce"
    local c=$1 out
    out=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null)
    local d="no" rc="-" b="no"
    echo "$out" | grep -q "DELIVERED: yes" && d="yes"
    rc=$(echo "$out" | grep -oP 'received_count=\K[-\d]+' | tail -1)
    echo "$out" | grep -q "BOUNCE: yes" && b="yes"
    echo "$d ${rc:--} $b"
}

dumpsize() { # caseid -> raw byte count stored in mailpit (0 if absent)
    local c=$1
    $MC /scripts/check_delivery.py --dump-case "$c" 2>/dev/null | wc -c
}

############################################
log "E0: reconfigure postfix1/postfix1n to single-hop (-> mailpit)"
docker exec postfix1  postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1  postfix reload >/dev/null
docker exec postfix1n postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1n postfix reload >/dev/null
sleep 2

############################################
log "E1: count ceiling scan"
CSV=$OUT/e1_ceiling.csv
echo "target,N,smtp_code,message_bytes,delivered,final_received,bounce" > $CSV
NS="0 5 10 15 20 25 30 35 40 44 45 46 47 48 49 50 51 52 53 54 55 60 70 80 100 120"
for tgt in "postfix1 25 PF37" "postfix1n 25 PF11" "exim 25 EXIM" "opensmtpd 25 OSMTPD" "mailpit 1025 MAILPIT"; do
    set -- $tgt; s=$1; p=$2; tag=$3
    log "E1 target=$tag"
    for n in $NS; do
        c="E1-${tag}-N$(printf %03d $n)"
        read code bytes <<< "$(send $s $p $c -n $n)"
        [ "$code" = "ERR" ] && { echo "$tag,$n,$code,$bytes,no,-,no" >> $CSV; continue; }
        read d rc b <<< "$(check $c)"
        echo "$tag,$n,$code,$bytes,$d,$rc,$b" >> $CSV
    done
done
log "E1 done"

############################################
log "E2: byte ceiling scan (folded 90KB x N)"
CSV=$OUT/e2_bytes.csv
echo "target,N,smtp_code,message_bytes,stored_bytes,delivered,final_received,bounce" > $CSV
NS2="1 2 3 5 10 20 40 60 80 100 120"
for tgt in "postfix1 25 PF37" "postfix1n 25 PF11" "exim 25 EXIM" "opensmtpd 25 OSMTPD" "mailpit 1025 MAILPIT"; do
    set -- $tgt; s=$1; p=$2; tag=$3
    log "E2 target=$tag"
    for n in $NS2; do
        c="E2-${tag}-F$(printf %03d $n)"
        read code bytes <<< "$(send $s $p $c --style folded -n $n --fold-kb 90)"
        if [ "$code" = "ERR" ] || [ "${code:0:1}" != "2" ]; then
            echo "$tag,$n,$code,$bytes,0,no,-,no" >> $CSV; continue
        fi
        read d rc b <<< "$(check $c)"
        stored=$(dumpsize $c)
        echo "$tag,$n,$code,$bytes,$stored,$d,$rc,$b" >> $CSV
    done
done
log "E2 done"

############################################
log "E3: blind-spot matrix (+parser view)"
CSV=$OUT/e3_blind.csv
echo "target,variant,N,smtp_code,delivered,final_received_exact,py_received,node_received,go_received" > $CSV
# variant -> header-name passed as a single quoted arg (names contain space/tab)
vname() {
    case $1 in
        rEcEiVeD)     printf 'rEcEiVeD';;
        received_sp)  printf 'Received ';;
        received_tab) printf 'Received\t';;
        utf8)         printf 'Receíved';;
        xreceived)    printf 'X-Received';;
    esac
}
for tgt in "postfix1 25 PF37" "postfix1n 25 PF11" "exim 25 EXIM" "opensmtpd 25 OSMTPD"; do
    set -- $tgt; s=$1; p=$2; tag=$3
    log "E3 target=$tag"
    for v in rEcEiVeD received_sp received_tab utf8 xreceived; do
        c="E3-${tag}-${v}"
        NAME=$(vname $v)
        read code bytes <<< "$(send $s $p $c -n 100 --header-name "$NAME")"
        if [ "$code" = "ERR" ] || [ "${code:0:1}" != "2" ]; then
            echo "$tag,$v,100,$code,no,-,-,-,-" >> $CSV; continue
        fi
        read d rc b <<< "$(check $c)"
        py=-; no=-; go=-
        if [ "$d" = "yes" ]; then
            $MC /scripts/check_delivery.py --dump-case "$c" > "$OUT/e3raw/$c.eml" 2>/dev/null
            py=$($MC /scripts/parse_python.py "/results/e-series/e3raw/$c.eml" 2>/dev/null | grep -oP '"received_count":\K\d+')
            no=$(docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "/results/e-series/e3raw/$c.eml" 2>/dev/null | grep -oP '"received_count":\K\d+')
            go=$(docker exec parser-go /usr/local/bin/parse_go "/results/e-series/e3raw/$c.eml" 2>/dev/null | grep -oP '"received_count":\K\d+')
        fi
        echo "$tag,$v,100,$code,$d,$rc,${py:-ERR},${no:-ERR},${go:-ERR}" >> $CSV
    done
    # resent blocks
    c="E3-${tag}-resent"
    read code bytes <<< "$(send $s $p $c --style resent -n 100)"
    if [ "${code:0:1}" = "2" ]; then
        read d rc b <<< "$(check $c)"
        echo "$tag,resent,100,$code,$d,$rc,-,-,-" >> $CSV
    else
        echo "$tag,resent,100,$code,no,-,-,-,-" >> $CSV
    fi
done
log "E3 done"

############################################
log "E4: heterogeneous chain client->opensmtpd->exim->postfix1->mailpit"
docker exec opensmtpd sh -c "sed -i 's|smtp://mailpit:1025|smtp://exim:25|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker restart opensmtpd >/dev/null
docker exec exim sh -c "sed -i 's|route_list = \* mailpit byname|route_list = * postfix1 byname|; s|port = 1025|port = 25|' /etc/exim/exim.conf"
docker restart exim >/dev/null
sleep 4
CSV=$OUT/e4_chain.csv
echo "N,smtp_code_from_opensmtpd,message_bytes,delivered,final_received,bounce" > $CSV
for n in 0 10 46 47 48 60 100 120; do
    c="E4-CHAIN-N$(printf %03d $n)"
    read code bytes <<< "$(send opensmtpd 25 $c -n $n)"
    read d rc b <<< "$(check $c)"
    echo "$n,$code,$bytes,$d,$rc,$b" >> $CSV
done
log "E4 done; restoring opensmtpd/exim -> mailpit"
docker exec opensmtpd sh -c "sed -i 's|smtp://exim:25|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker exec exim sh -c "sed -i 's|route_list = \* postfix1 byname|route_list = * mailpit byname|; s|port = 25|port = 1025|' /etc/exim/exim.conf"
docker restart opensmtpd exim >/dev/null

############################################
log "E5: amplification - big header block x loop"
# restore standard 3-hop chain, P3 -> P1, limit 8
docker exec postfix1  postconf -e 'relayhost = [postfix2]:25'
docker exec postfix1  postconf -e 'hopcount_limit = 8'
docker exec postfix2  postconf -e 'hopcount_limit = 8'
docker exec postfix3  postconf -e 'hopcount_limit = 8'
docker exec postfix3  postconf -e 'relayhost = [postfix1]:25'
for h in postfix1 postfix2 postfix3; do docker exec $h postfix reload >/dev/null; done
sleep 2
CSV=$OUT/e5_amplify.csv
echo "case,header_block,message_bytes,sizes_per_cycle_bytes,dsn_size_bytes,notes" > $CSV
for blk in "0 CTRL" "5 5x90KB"; do
    set -- $blk; nf=$1; label=$2
    c="E5-$label"
    before=$(docker logs postfix1 2>&1 | wc -l)
    if [ "$nf" = "0" ]; then
        read code bytes <<< "$(send postfix1 25 $c -n 0)"
    else
        read code bytes <<< "$(send postfix1 25 $c --style folded -n $nf --fold-kb 90)"
    fi
    sleep 35
    docker logs postfix1 2>&1 | tail -n +$((before+1)) > "$OUT/e5_${label}.log"
    # qmgr logs one from=<alice,...>, size=N line per loop cycle -> growth curve
    sizes=$(grep "from=<alice@sender.lab.test>" "$OUT/e5_${label}.log" | grep -oP 'size=\K\d+' | paste -sd';' -)
    # DSN from=<> line size
    dsn=$(grep 'from=<>' "$OUT/e5_${label}.log" | grep -oP 'size=\K\d+' | tail -1)
    hops=$(grep -c 'too many hops' "$OUT/e5_${label}.log")
    echo "$c,$label,$bytes,${sizes:-0},${dsn:-0},code=$code too_many_hops_lines=$hops" >> $CSV
done
log "E5 done"

############################################
log "restore standard topology"
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'
docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
docker exec postfix1n postconf -e 'relayhost = [postfix2n]:25'
docker exec postfix2n postconf -e 'relayhost = [postfix3n]:25'
docker exec postfix3n postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3 postfix1n postfix2n postfix3n; do
    docker exec $h postconf -e 'hopcount_limit = 50'; docker exec $h postfix reload >/dev/null
done
log "E-SERIES ALL DONE"
