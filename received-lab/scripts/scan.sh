#!/bin/bash
# Received hop-count boundary scan.
# usage: scan.sh <output_csv> <start_N> <end_N> [header_name] [case_prefix]
# Run from WSL with docker available. Writes CSV plus per-case evidence logs.
set -u
cd "$(dirname "$0")/.."
OUT="$1"; START="$2"; END="$3"
HEADER_NAME="${4:-Received}"
PREFIX="${5:-C}"
mkdir -p results/logs

csv_escape() { local v="$1"; v="${v//,/;}"; printf '%s' "$v"; }

# classify one node's log delta: $1 = delta file, $2 = expected inbound queue id ("" if unknown)
node_classify() {
    local f="$1" qid="$2"
    if grep -q "status=bounced" "$f"; then
        echo "accept;relay=bounced"; return
    fi
    if grep -q "hopcount exceeded" "$f"; then
        echo "rejected_hopcount_exceeded"; return
    fi
    if [ -n "$qid" ] && grep -qE "smtpd\[[0-9]+\]: $qid: client=" "$f"; then
        if grep -q "status=sent" "$f"; then echo "accept;relay=sent"
        elif grep -q "status=deferred" "$f"; then echo "accept;relay=deferred"
        else echo "accept;queued_only"; fi
    else
        echo "no_traffic"
    fi
}

# queue id assigned by the *next* hop, extracted from bob's delivery status line
extract_next_qid() {
    grep "to=<bob@receiver.lab.test>" "$1" | grep -oP "queued as \K[0-9A-F]+" | tail -1
}

colhdr_count="fake_received_count"
[ "$HEADER_NAME" != "Received" ] && colhdr_count="fake_${HEADER_NAME}_count"
if [ ! -s "$OUT" ]; then
    echo "case_id,${colhdr_count},real_hops,smtp_code,postfix1_result,postfix2_result,postfix3_result,final_received_count,queue_status" > "$OUT"
fi

N=$START
while [ "$N" -le "$END" ]; do
    CASE=$(printf "%s%03d" "$PREFIX" "$N")
    o1=$(docker logs postfix1 2>&1 | wc -l)
    o2=$(docker logs postfix2 2>&1 | wc -l)
    o3=$(docker logs postfix3 2>&1 | wc -l)

    docker exec mail-client python3 /scripts/send_received.py \
        -n "$N" --header-name "$HEADER_NAME" --case-id "$CASE" \
        > "results/logs/$CASE.smtp.log" 2>&1
    code=$(grep -oP 'DATA_REPLY: \K[0-9]{3}' "results/logs/$CASE.smtp.log" | tail -1)
    qid1=$(grep -oP 'queued as \K[0-9A-F]+' "results/logs/$CASE.smtp.log" | tail -1)

    delivered=""; rcnt=""; bounce=""
    if [ "$code" = "250" ]; then
        docker exec mail-client python3 /scripts/check_delivery.py \
            --case-id "$CASE" --timeout 15 > "results/logs/$CASE.check.log" 2>&1
        delivered=$(grep -oP '^DELIVERED: \K\S+' "results/logs/$CASE.check.log")
        rcnt=$(grep -oP 'received_count=\K[0-9]+' "results/logs/$CASE.check.log")
        bounce=$(grep -oP '^BOUNCE: \K\S+' "results/logs/$CASE.check.log")
    else
        delivered="no"; bounce="no"
    fi

    docker logs postfix1 2>&1 | tail -n +$((o1+1)) > "results/logs/$CASE.p1.log"
    docker logs postfix2 2>&1 | tail -n +$((o2+1)) > "results/logs/$CASE.p2.log"
    docker logs postfix3 2>&1 | tail -n +$((o3+1)) > "results/logs/$CASE.p3.log"

    p1=$(node_classify "results/logs/$CASE.p1.log" "$qid1")
    q2=$(extract_next_qid "results/logs/$CASE.p1.log")
    p2=$(node_classify "results/logs/$CASE.p2.log" "$q2")
    q3=$(extract_next_qid "results/logs/$CASE.p2.log")
    p3=$(node_classify "results/logs/$CASE.p3.log" "$q3")

    if [ "$code" != "250" ]; then qstatus="rejected_at_data($code)"
    elif [ "$delivered" = "yes" ]; then qstatus="delivered"
    elif [ "$bounce" = "yes" ]; then qstatus="bounced_not_delivered"
    else qstatus="unknown"; fi

    echo "$CASE,$N,3,$code,$(csv_escape "$p1"),$(csv_escape "$p2"),$(csv_escape "$p3"),${rcnt:-},$qstatus" >> "$OUT"
    echo "[$CASE] n=$N header=$HEADER_NAME code=$code delivered=$delivered rcv=${rcnt:--} bounce=$bounce status=$qstatus | p1=$p1 p2=$p2 p3=$p3"
    N=$((N+1))
done
echo "scan done -> $OUT"
