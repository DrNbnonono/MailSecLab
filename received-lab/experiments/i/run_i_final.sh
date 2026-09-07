#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
keepup() { docker compose --profile frspamd --profile mta3b --profile pf11 up -d >/dev/null 2>&1; }

log "== exim.conf repair (transport name corrupted by port-sed inside 'transport=') =="
keepup; sleep 2
docker cp exim/exim.conf exim:/etc/exim/exim.conf
docker exec exim sh -c "sed -i 's|^  port = .*|  port = 1025|' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 3
docker exec exim exim -qf >/dev/null 2>&1 &
log "exim.conf reset from pristine; deferred queue flushed"

log "== I1-retry2: exim pairs with ANCHORED seds =="
retarget_exim() { # mta2
    docker exec exim sh -c "sed -i 's|^  route_list = .*|  route_list = * $1 byname|; s|^  port = .*|  port = 25|' /etc/exim/exim.conf"
    keepup; docker restart exim >/dev/null; sleep 2
}
echo "mta1,mta2,sep,bdat_reply,first_delivered,smuggled_delivered" > $OUT/i1_exim_retry.csv
for pair in "postfix2" "postfix2n" "mailpit"; do
    m2=$pair
    case $m2 in
      postfix2)  docker exec postfix2  postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2  postfix reload >/dev/null 2>&1;;
      postfix2n) docker exec postfix2n postconf -e 'relayhost = [mailpit]:1025' 2>/dev/null; docker exec postfix2n postfix reload >/dev/null 2>&1;;
    esac
    retarget_exim $m2
    for sep in crlf lf; do
        keepup; sleep 1
        c="I1X-exim-to-$m2-$sep"
        $MC /scripts/mk_i1_payload.py $c $sep >/dev/null
        r=$($MC /scripts/send_bdat.py exim 25 /results/i-series/$c.payload $c 2>&1 | grep -oE 'BDAT_REPLY: .*' | head -1)
        sleep 4
        keepup; sleep 1
        docker exec exim exim -qf >/dev/null 2>&1 &
        f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes")
        s=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 15 2>/dev/null | grep -c "DELIVERED: yes")
        echo "exim,$m2,$sep,$r,$f/$s" >> $OUT/i1_exim_retry.csv
        echo "  $c -> $r first/smug=$f/$s" | tee -a $REC
    done
done
retarget_exim mailpit
docker exec exim sh -c "sed -i 's|^  port = .*|  port = 1025|' /etc/exim/exim.conf"
docker restart exim >/dev/null

log "== I2: chain-consistent spoof vs rspamd =="
docker exec rspamd sh -c 'printf "level = \"debug\";\n" > /etc/rspamd/local.d/logging.inc' 2>/dev/null
docker restart rspamd >/dev/null; sleep 3
for i in $(seq 1 40); do docker exec rspamd sh -c 'printf "X: 1\r\n\r\n" > /tmp/t.eml; rspamc /tmp/t.eml' >/dev/null 2>&1 && break; sleep 2; done
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null; sleep 1
echo "mode,score,action,derived_ip" > $OUT/i2_chain.csv
for mode in plain consistent inconsistent; do
    c="I2-$mode"
    $MC /scripts/mk_i2_msg.py /results/i-series/$c.eml $c $mode
    $MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/i-series/$c.eml --case-id $c 2>&1 | grep DATA_REPLY | tee -a $REC
    sleep 3
    $MC /scripts/check_delivery.py --dump-case $c > $OUT/$c.stored.eml 2>/dev/null
    rj=$(docker exec rspamd rspamc --json /results/i-series/$c.stored.eml 2>/dev/null)
    echo "$rj" > $OUT/${c}.json
    sleep 1
    read score action ip <<< "$(docker exec rspamd grep "file: /results/i-series/$c.stored.eml" /var/log/rspamd/rspamd.log | grep -oP 'ip: \K[0-9.]+' | tail -1) | $(echo "$rj" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('score'), d.get('action'))" 2>/dev/null)"
    ip=${ip% | *}
    echo "$mode,${score:-?},${action:-?},${ip:-UNKNOWN}" >> $OUT/i2_chain.csv
    echo "  I2 $mode: score=$score action=$action derived_ip=$ip" | tee -a $REC
done
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'; docker exec postfix1 postfix reload >/dev/null
log "== I-FINAL DONE =="
