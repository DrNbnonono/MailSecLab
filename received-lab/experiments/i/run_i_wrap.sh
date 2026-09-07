#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
# keep VM busy so resource-saver doesn't kill containers mid-run
( while :; do echo tick >/dev/null; docker info >/dev/null 2>&1; sleep 5; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
keepup() { docker compose --profile frspamd --profile mta3b --profile pf11 up -d >/dev/null 2>&1; }

log "== I2 proper extraction =="
keepup; sleep 2
docker exec rspamd sh -c 'printf "level = \"debug\";\n" > /etc/rspamd/local.d/logging.inc' 2>/dev/null
docker start rspamd >/dev/null 2>&1; docker restart rspamd >/dev/null 2>&1; sleep 3
for i in $(seq 1 40); do docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done
echo "mode,score,action,derived_ip" > $OUT/i2_chain.csv
for mode in plain consistent inconsistent; do
    c="I2-$mode"
    docker exec rspamd sh -c "grep \"file: /results/i-series/$c.stored.eml\" /var/log/rspamd/rspamd.log" > /tmp/i2_$mode.log 2>/dev/null
    line=$(grep -oP 'ip: \K[0-9.]+' /tmp/i2_$mode.log | tail -1)
    rj=$(docker exec rspamd rspamc --json /results/i-series/$c.stored.eml 2>/dev/null)
    echo "$rj" > $OUT/${c}.json
    score=$(echo "$rj" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin); print(d.get('score'), '|', d.get('action'))
except: print('ERR|')")
    echo "$mode,${score%%|*},${score##*|},${line:-UNKNOWN}" >> $OUT/i2_chain.csv
    echo "  I2 $mode: $score derived_ip=${line:-UNKNOWN}" | tee -a $REC
done

log "== exim pairs with retry wrapper =="
retarget_exim() {
    docker exec exim sh -c "sed -i 's|^  route_list = .*|  route_list = * $1 byname|; s|^  port = .*|  port = 25|' /etc/exim/exim.conf" 2>/dev/null
    keepup; docker restart exim >/dev/null 2>&1; sleep 2
}
restore_exim() {
    docker exec exim sh -c "sed -i 's|^  route_list = .*|  route_list = * mailpit byname|; s|^  port = .*|  port = 1025|' /etc/exim/exim.conf" 2>/dev/null
    keepup; docker restart exim >/dev/null 2>&1; sleep 1
}
echo "mta1,mta2,sep,bdat_reply,first,smug" > $OUT/i1_exim_retry.csv
for pair in "postfix2" "postfix2n" "mailpit"; do
    m2=$pair
    case $m2 in
      postfix2)  docker exec postfix2  postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2  postfix reload >/dev/null 2>&1;;
      postfix2n) docker exec postfix2n postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1;;
    esac
    retarget_exim $m2
    for sep in crlf lf; do
        c="I1Z-exim-to-$m2-$sep"
        ok=""
        for attempt in 1 2 3; do
            keepup; sleep 1
            docker start exim >/dev/null 2>&1; sleep 1
            $MC /scripts/mk_i1_payload.py $c $sep >/dev/null 2>&1
            r=$($MC /scripts/send_bdat.py exim 25 /results/i-series/$c.payload $c 2>&1 | grep -oE 'BDAT_REPLY: .*' | head -1)
            [ -z "$r" ] && continue
            sleep 3; keepup; sleep 1
            docker exec exim exim -qf >/dev/null 2>&1 &
            sleep 2
            f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 10 2>/dev/null | grep -c "DELIVERED: yes")
            sm=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 10 2>/dev/null | grep -c "DELIVERED: yes")
            if [ "$f" -ge 1 ]; then ok="yes"; break; fi
        done
        echo "exim,$m2,$sep,$r,$f/$sm" >> $OUT/i1_exim_retry.csv
        echo "  $c (attempt $attempt) -> $r first/smug=$f/$sm" | tee -a $REC
    done
done
restore_exim
docker exec postfix2  postconf -e 'relayhost = [postfix3]:25' 2>/dev/null; docker exec postfix2  postfix reload >/dev/null 2>&1
docker exec postfix2n postconf -e 'relayhost = [postfix3n]:25' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1
log "== I-WRAP DONE =="
