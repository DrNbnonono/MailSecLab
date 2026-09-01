#!/bin/bash
# Phase 2: RFC unbounded-growth path experiments.
# usage: phase2.sh
# Runs a fixed set of cases (Resent blocks / folded giants / duplicate max-1
# fields / look-alike Received names / ARC triplets), appends results/phase2.csv.
set -u
cd "$(dirname "$0")/.."
mkdir -p results/logs
OUT=results/phase2.csv
[ -s "$OUT" ] || echo "case_id,description,smtp_code,postfix1_result,postfix2_result,postfix3_result,delivered,received_exact,received_ci,received_ws_variant,received_in_body,largest_header_bytes,notes" > "$OUT"

csv_escape() { local v="$1"; v="${v//,/;}"; printf '%s' "$v"; }

node_classify() {
    local f="$1" qid="$2"
    if grep -q "status=bounced" "$f"; then echo "accept;relay=bounced"; return; fi
    if grep -q "hopcount exceeded" "$f"; then echo "rejected_hopcount_exceeded"; return; fi
    if [ -n "$qid" ] && grep -qE "smtpd\[[0-9]+\]: $qid: client=" "$f"; then
        if grep -q "status=sent" "$f"; then echo "accept;relay=sent"
        elif grep -q "status=deferred" "$f"; then echo "accept;relay=deferred"
        else echo "accept;queued_only"; fi
    else
        echo "no_traffic"
    fi
}

extract_next_qid() {
    grep "to=<bob@receiver.lab.test>" "$1" | grep -oP "queued as \K[0-9A-F]+" | tail -1
}

# run_case CASE DESC NOTES [inspect --name args...] -- [sender args...]
run_case() {
    local CASE="$1" DESC="$2" NOTES="$3"; shift 3
    local INSPECT_ARGS=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        [ -n "$1" ] && INSPECT_ARGS+=("$1")
        shift
    done
    [ $# -gt 0 ] && shift

    local o1 o2 o3
    o1=$(docker logs postfix1 2>&1 | wc -l)
    o2=$(docker logs postfix2 2>&1 | wc -l)
    o3=$(docker logs postfix3 2>&1 | wc -l)

    docker exec mail-client python3 /scripts/send_received.py --case-id "$CASE" "$@" \
        > "results/logs/$CASE.smtp.log" 2>&1
    local code bytes
    code=$(grep -oP 'DATA_REPLY: \K[0-9]{3}' "results/logs/$CASE.smtp.log" | tail -1)
    bytes=$(grep -oP 'MESSAGE_BYTES: \K[0-9]+' "results/logs/$CASE.smtp.log" | tail -1)

    docker exec mail-client python3 /scripts/check_delivery.py --case-id "$CASE" --timeout 12 \
        > "results/logs/$CASE.check.log" 2>&1
    local bounce
    bounce=$(grep -oP '^BOUNCE: \K\S+' "results/logs/$CASE.check.log")

    docker exec mail-client python3 /scripts/inspect_raw.py --case-id "$CASE" --timeout 12 \
        "${INSPECT_ARGS[@]}" > "results/logs/$CASE.inspect.log" 2>&1
    local delivered rcv_exact rcv_ci rcv_ws rcv_body largest
    delivered=$(grep -oP '^FOUND: \K\S+' "results/logs/$CASE.inspect.log")
    rcv_exact=$(grep -oP '^RECEIVED_EXACT: \K[0-9]+' "results/logs/$CASE.inspect.log")
    rcv_ci=$(grep -oP '^RECEIVED_CI: \K[0-9]+' "results/logs/$CASE.inspect.log")
    rcv_ws=$(grep -oP '^RECEIVED_SPACE: \K[0-9]+' "results/logs/$CASE.inspect.log")
    rcv_body=$(grep -oP '^RECEIVED_IN_BODY: \K[0-9]+' "results/logs/$CASE.inspect.log")
    largest=$(grep -oP '^LARGEST_HEADER_BYTES: \K[0-9]+' "results/logs/$CASE.inspect.log")

    docker logs postfix1 2>&1 | tail -n +$((o1+1)) > "results/logs/$CASE.p1.log"
    docker logs postfix2 2>&1 | tail -n +$((o2+1)) > "results/logs/$CASE.p2.log"
    docker logs postfix3 2>&1 | tail -n +$((o3+1)) > "results/logs/$CASE.p3.log"
    local qid1 p1 q2 p2 q3 p3
    qid1=$(grep -oP 'queued as \K[0-9A-F]+' "results/logs/$CASE.smtp.log" | tail -1)
    p1=$(node_classify "results/logs/$CASE.p1.log" "$qid1")
    q2=$(extract_next_qid "results/logs/$CASE.p1.log")
    p2=$(node_classify "results/logs/$CASE.p2.log" "$q2")
    q3=$(extract_next_qid "results/logs/$CASE.p2.log")
    p3=$(node_classify "results/logs/$CASE.p3.log" "$q3")

    echo "$CASE,$(csv_escape "$DESC"),$code,$(csv_escape "$p1"),$(csv_escape "$p2"),$(csv_escape "$p3"),${delivered:--},${rcv_exact:--},${rcv_ci:--},${rcv_ws:--},${rcv_body:--},${largest:--},$(csv_escape "${NOTES}bytes=$bytes bounce=$bounce")" >> "$OUT"
    echo "[$CASE] code=$code delivered=${delivered:--} rcv_exact=${rcv_exact:--} rcv_ci=${rcv_ci:--} rcv_ws=${rcv_ws:--} rcv_body=${rcv_body:--} bounce=$bounce bytes=$bytes | p1=$p1 p2=$p2 p3=$p3"
}

echo "===== B: Resent-* blocks (hopcount should ignore them) ====="
run_case RB010 "Resent x10 blocks (40 hdrs)"        "" --name Resent-Date -- --style resent -n 10
run_case RB100 "Resent x100 blocks (400 hdrs)"      "" --name Resent-Date -- --style resent -n 100
run_case RB300 "Resent x300 blocks (1200 hdrs)"     "" --name Resent-Date -- --style resent -n 300

echo "===== C: giant folded Received (size dimension) ====="
run_case FC090 "3x folded Received ~90KB each"      "" --name Received -- --style folded -n 3 --fold-kb 90
run_case FC150 "1x folded Received ~150KB (> header_size_limit 102400)" "" --name Received -- --style folded -n 1 --fold-kb 150
run_case FC500 "5x folded Received ~90KB (450KB)"   "" --name Received -- --style folded -n 5 --fold-kb 90

echo "===== D: duplicate max-1 fields ====="
run_case DS050 "Subject x50 (RFC 5322 max=1 violated)" "" --name Subject -- --header-name Subject -n 50
run_case DM050 "Message-ID x50 (RFC 5322 max=1 violated)" "" --name Message-ID -- --header-name Message-ID -n 50
run_case DC100 "Comments x100 (unlimited field, control)" "" --name Comments -- --header-name Comments -n 100

echo "===== E: look-alike Received names ====="
run_case EW005 "'Received :' (space) x5 — pass-through & counting check" "" "" -- --header-name "Received " -n 5
run_case EWT05 "'Received<TAB>:' x5 — pass-through & counting check" "" "" -- --header-name $'Received\t' -n 5
run_case EW100 "'Received :' (space before colon) x100" "" "" -- --header-name "Received " -n 100
run_case ET050 "'Receíved' (UTF-8 look-alike) x50" "" "" -- --header-name "Receíved" -n 50

echo "===== F: ARC-style triplets + boundary independence ====="
run_case AF100 "ARC-style 100 triplets (300 hdrs)"  "" --name ARC-Seal -- --style arc -n 100
run_case RW046 "46 Received + 100 X-Received (boundary control: deliver)" "" "" -- -n 46 --extra-count 100 --extra-name "X-Received"
run_case RW047 "47 Received + 100 X-Received (boundary control: bounce)" "" "" -- -n 47 --extra-count 100 --extra-name "X-Received"

echo "phase2 done -> $OUT"
