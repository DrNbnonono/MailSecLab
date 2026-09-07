#!/bin/bash
# F2 rerun with EXPLICIT pre-reset (lesson from run-1: crashed F4 left hopcount=8
# on postfix1, which silently invalidated all F2 cases via "hopcount exceeded").
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/f-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
send() { local s=$1 p=$2 c=$3; shift 3
    local out; out=$($MC /scripts/send_received.py --server "$s" --port "$p" --case-id "$c" "$@" 2>/dev/null)
    echo "$(echo "$out" | grep -oP 'DATA_REPLY: \K.*' | tail -1)|$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+' | tail -1)"; }
check() { local c=$1
    $MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null |
      grep -E "DELIVERED|BOUNCE" | tr '\n' ' '; }

log "== F2 rerun: PRE-RESET topology first =="
docker exec postfix1 postconf -e 'hopcount_limit = 50'
docker exec postfix2 postconf -e 'hopcount_limit = 50'
docker exec postfix3 postconf -e 'hopcount_limit = 50'
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'
docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'
docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3; do docker exec $h postfix reload >/dev/null; done
docker exec exim sh -c "sed -i '/^received_headers_max/d; /^header_maxsize/d' /etc/exim/exim.conf"
docker exec opensmtpd sh -c "sed -i 's|smtp://postfix1:25|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker exec opensmtpd sh -c "sed -i 's|smtp://exim:25|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"
sleep 1
echo -n "pre-reset check: postfix1 " | tee -a $REC
docker exec postfix1 postconf hopcount_limit relayhost | tr '\n' ' ' | tee -a $REC
echo "" | tee -a $REC

# route: osmtpd -> postfix1(single-hop -> mailpit)
docker exec opensmtpd sh -c "sed -i 's|smtp://mailpit:1025|smtp://postfix1:25|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker restart opensmtpd >/dev/null; sleep 3

CSV=$OUT/f2_hidden.csv
echo "path,N,osmtpd_code,final_delivered,exact,wsp,ci,node_received,notes" > $CSV
run_f2() {
    local tgt=$1
    local n=$2
    local c="F2R-$tgt-N$n"
    local res; res=$(send opensmtpd 25 $c -n $n --header-name "Received ")
    local code=${res%%|*}
    local d="no" ex="-" wsp="-" ci="-" nrc="-" note=""
    if echo "$code" | grep -q '^2'; then
        local chk; chk=$(check $c)
        echo "$chk" | grep -q "DELIVERED: yes" && d="yes"
        if [ "$d" = "yes" ]; then
            $MC /scripts/check_delivery.py --dump-case "$c" > "$OUT/logs/$c.eml" 2>/dev/null
            local cnts; cnts=$($MC /scripts/count_received.py "/results/f-series/logs/$c.eml" 2>/dev/null)
            ex=$(echo "$cnts" | grep -oP '"received_exact":\K\d+')
            wsp=$(echo "$cnts" | grep -oP '"received_wsp":\K\d+')
            ci=$(echo "$cnts" | grep -oP '"received_ci":\K\d+')
            nrc=$(docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "/results/f-series/logs/$c.eml" 2>/dev/null | grep -oP '"received_count":\K\d+')
        fi
        echo "$chk" | grep -q "BOUNCE: yes" && note="bounced(DSN in mailpit)"
    else
        note="not accepted by osmtpd"
    fi
    echo "$tgt,$n,$code,$d,$ex,$wsp,$ci,${nrc:--},$note" >> $CSV
    echo "  F2R $tgt N=$n code=$(echo $code | cut -c1-3) delivered=$d exact=$ex wsp=$wsp ci=$ci node=$nrc $note" | tee -a $REC
}
run_f2 PF 40
run_f2 PF 100
# route: osmtpd -> exim -> postfix1 -> mailpit (exim default received_headers_max=30)
docker exec exim sh -c "sed -i 's|route_list = \* mailpit byname|route_list = * postfix1 byname|; s|port = 1025|port = 25|' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 3
run_f2 EX 25
run_f2 EX 100
log "F2 rerun done; restoring osmtpd/exim/postfix1"
docker exec opensmtpd sh -c "sed -i 's|smtp://postfix1:25|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker exec exim sh -c "sed -i 's|route_list = \* postfix1 byname|route_list = * mailpit byname|; s|port = 25|port = 1025|' /etc/exim/exim.conf"
docker restart opensmtpd exim >/dev/null
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== F2 RERUN DONE, topology restored =="
