#!/bin/bash
# Refinements: pin exact boundaries found by E-series.
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/e-series
mkdir -p $OUT
MC="docker exec mail-client python3"
send() { local s=$1 p=$2 c=$3; shift 3
    local out; out=$($MC /scripts/send_received.py --server "$s" --port "$p" --case-id "$c" "$@" 2>/dev/null)
    echo "$out" | grep -oP 'DATA_REPLY: \K.*' | tail -1; }
check() { local c=$1
    $MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null |
      grep -E "DELIVERED|BOUNCE" | tr '\n' ' '; }

echo "== [R1] opensmtpd 500 boundary: header COUNT? =="
echo "N,smtp_reply,check" > $OUT/r1_osmtpd_count.csv
for n in 85 90 95 98 99 100 101 102; do
    c="R1-OS-N$n"
    r=$(send opensmtpd 25 $c -n $n)
    d=$(check $c)
    echo "$n,$r,$d" >> $OUT/r1_osmtpd_count.csv
    echo "N=$n -> $r | $d"
done

echo "== [R2] exim received_headers_max boundary N=26..31 =="
echo "N,smtp_reply,check" > $OUT/r2_exim_count.csv
for n in 26 27 28 29 30 31; do
    c="R2-EX-N$n"
    r=$(send exim 25 $c -n $n)
    d=$(check $c)
    echo "$n,$r,$d" >> $OUT/r2_exim_count.csv
    echo "N=$n -> $r | $d"
done

echo "== [R3] postfix byte channel: folded X-Received (hopcount-blind), 3-hop chain =="
echo "N,message_bytes,smtp_reply,delivered,stored_bytes" > $OUT/r3_pf_bytes.csv
for n in 50 90 100; do
    c="R3-PF-XF$n"
    out=$($MC /scripts/send_folded_xreceived.py $n $c postfix1 2>&1)
    reply=$(echo "$out" | grep -oP 'DATA_REPLY: \K.*')
    bytes=$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+')
    if echo "$reply" | grep -q '^2'; then
        d=$(check $c)
        stored=$($MC /scripts/check_delivery.py --dump-case "$c" 2>/dev/null | wc -c)
    else
        d="no"; stored=0
    fi
    echo "$n,$bytes,$reply,$d,$stored" >> $OUT/r3_pf_bytes.csv
    echo "N=$n bytes=$bytes -> $reply | $d stored=$stored"
done
echo "REFINE-DONE"
