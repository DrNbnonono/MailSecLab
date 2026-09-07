#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
keepup() { docker compose --profile frspamd up -d >/dev/null 2>&1; }

log "== I1 v2: self-healing matrix =="
keepup; sleep 2
retarget_mta1() { # mta1 mta2
    case $1 in
      exim) docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * $2 byname|; s|port = [0-9]*|port = 25|' /etc/exim/exim.conf"; keepup; docker restart exim >/dev/null 2>&1;;
      opensmtpd) docker exec opensmtpd sh -c "sed -i 's|smtp://[a-z0-9]*:[0-9]*|smtp://$2:25|' /etc/smtpd.conf /etc/mail/smtpd.conf"; keepup; docker restart opensmtpd >/dev/null 2>&1;;
      postfix1) docker exec postfix1 postconf -e "relayhost = [$2]:25"; docker exec postfix1 postfix reload >/dev/null 2>&1;;
    esac
}
echo "mta1,mta2,sep,bdat_reply,first_delivered,smuggled_delivered" > $OUT/i1_matrix.csv
for pair in "postfix1 postfix2" "postfix1 postfix2n" "postfix1 exim" "postfix1 opensmtpd" "postfix1 mailpit" \
            "exim postfix2" "exim postfix2n" "exim opensmtpd" "exim mailpit" \
            "opensmtpd postfix2" "opensmtpd postfix2n" "opensmtpd postfix1n" "opensmtpd mailpit"; do
    set -- $pair; m1=$1; m2=$2
    case $m2 in
      mailpit) : ;;
      postfix2)  keepup; docker exec postfix2  postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2  postfix reload >/dev/null 2>&1;;
      postfix2n) keepup; docker exec postfix2n postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1;;
      postfix1n) keepup; docker exec postfix1n postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix1n postfix reload >/dev/null 2>&1;;
    esac
    retarget_mta1 $m1 $m2
    sleep 2
    for sep in crlf lf; do
        keepup; sleep 1
        c="I1-${m1}-to-${m2}-${sep}"
        r=$($MC /scripts/send_bdat.py $m1 25 $OUT/$sep.payload 2>&1 | grep -E 'CHUNKING|BDAT_REPLY' | tr '\n' ' ')
        sleep 3
        keepup; sleep 1
        f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null | grep -c "DELIVERED: yes")
        s=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 8 2>/dev/null | grep -c "DELIVERED: yes")
        echo "$m1,$m2,$sep,$r,$f/$s" >> $OUT/i1_matrix.csv
        echo "  $c -> $r first/smug=$f/$s" | tee -a $REC
    done
done
# restore all relays
keepup
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null 2>&1
docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * mailpit byname|; s|port = [0-9]*|port = 1025|' /etc/exim/exim.conf" 2>/dev/null
docker exec opensmtpd sh -c "sed -i 's|smtp://[a-z0-9]*:[0-9]*|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf" 2>/dev/null
docker restart exim opensmtpd >/dev/null 2>&1
log "== I1 v2 DONE =="
