#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
keepup() { docker compose --profile frspamd --profile mta3b --profile pf11 up -d >/dev/null 2>&1; }
log "== exim conf from pristine + exim pairs (anchored seds only) =="
keepup; sleep 2
docker cp exim/exim.conf exim:/etc/exim/exim.conf
docker restart exim >/dev/null; sleep 3
retarget_exim() {
    docker exec exim sh -c "sed -i 's|^  route_list = .*|  route_list = * $1 byname|; s|^  port = .*|  port = 25|' /etc/exim/exim.conf"
    keepup; docker restart exim >/dev/null; sleep 2
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
        r="-"; f=0; sm=0
        for attempt in 1 2 3; do
            keepup; sleep 1
            docker start exim >/dev/null 2>&1; sleep 2
            $MC /scripts/mk_i1_payload.py $c $sep >/dev/null 2>&1
            r=$($MC /scripts/send_bdat.py exim 25 /results/i-series/$c.payload $c 2>&1 | grep -oE 'BDAT_REPLY: .*' | head -1)
            [ -z "$r" ] && { echo "  $c attempt $attempt: send failed ($r)" | tee -a $REC; continue; }
            sleep 3; keepup; sleep 1
            docker exec exim exim -qf >/dev/null 2>&1 &
            sleep 2
            f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 10 2>/dev/null | grep -c "DELIVERED: yes")
            sm=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 10 2>/dev/null | grep -c "DELIVERED: yes")
            [ "$f" -ge 1 ] && break
        done
        echo "exim,$m2,$sep,$r,$f/$sm" >> $OUT/i1_exim_retry.csv
        echo "  $c attempt=$attempt -> $r first/smug=$f/$sm" | tee -a $REC
    done
done
docker exec exim sh -c "sed -i 's|^  port = .*|  port = 1025|' /etc/exim/exim.conf" 2>/dev/null
docker exec postfix2  postconf -e 'relayhost = [postfix3]:25' 2>/dev/null;  docker exec postfix2  postfix reload >/dev/null 2>&1
docker exec postfix2n postconf -e 'relayhost = [postfix3n]:25' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1
log "== EXIM-FIX DONE =="
