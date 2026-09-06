#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
keepup() { docker compose --profile frspamd --profile mta3b --profile pf11 up -d >/dev/null 2>&1; }
log "== I1 retry: previously infrastructure-failed pairs =="
retarget_mta1() {
    case $1 in
      exim) docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * $2 byname|; s|port = [0-9]*|port = 25|' /etc/exim/exim.conf"; keepup; docker restart exim >/dev/null 2>&1;;
      postfix1)
        if [ "$2" = mailpit ]; then docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025';
        else docker exec postfix1 postconf -e "relayhost = [$2]:25"; fi
        docker exec postfix1 postfix reload >/dev/null 2>&1;;
    esac
}
for pair in "postfix1 postfix2n" "postfix1 exim" "postfix1 mailpit" "exim postfix2" "exim postfix2n" "exim mailpit"; do
    set -- $pair; m1=$1; m2=$2
    case $m2 in
      postfix2)  docker exec postfix2  postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2  postfix reload >/dev/null 2>&1;;
      postfix2n) docker exec postfix2n postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1;;
    esac
    retarget_mta1 $m1 $m2
    sleep 2
    for sep in crlf lf; do
        keepup; sleep 1
        c="I1R-$m1-to-$m2-$sep"
        docker exec mail-client python3 /scripts/mk_i1_payload.py $c $sep >/dev/null
        r=$($MC /scripts/send_bdat.py $m1 25 /results/i-series/$c.payload $c 2>&1 | grep -oE 'BDAT_REPLY: .*' | head -1)
        sleep 5
        keepup; sleep 1
        docker exec postfix1 postqueue -f >/dev/null 2>&1
        f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes")
        s=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes")
        sleep 3
        f2=$f; s2=$s
        if [ "$f" = "0" ]; then f2=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes"); s2=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes"); fi
        echo "$m1,$m2,$sep,$r,$f2/$s2" >> $OUT/i1_matrix.csv
        echo "  retry $c -> $r first/smug=$f2/$s2" | tee -a $REC
    done
done
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null 2>&1
docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * mailpit byname|; s|port = [0-9]*|port = 1025|' /etc/exim/exim.conf" 2>/dev/null
docker restart exim >/dev/null 2>&1
log "== I1 retry DONE =="
