#!/bin/bash
# Phase 3A: run the byte-fixed corpus across Postfix versions and
# non_empty_end_of_header_action policies.
#
# usage: phase3.sh [rounds...]     rounds: pf37 pf11 (default: both)
#
# Matrix: {PF37}x{default} and {PF11}x{default,fix_quietly,add_header,reject}.
# Evidence per case: results/phase3/<ENV>/<POLICY>/<CASE>/ with input.eml,
# <CASE>.raw.eml/.sha256/.parsed.json (Mailpit output bytes), smtp log,
# per-node log deltas, inspect.log and result.json. Matrix rows append to
# results/phase3/matrix.csv.
set -u
cd "$(dirname "$0")/.."
BASE=results/phase3
CORPUS_IN=/results/phase3/corpus
NAMES=(--name Received --name From --name To --name Subject --name Message-ID --name X-Case-ID --name MIME-Error)
CASES="V001 V002 V003 V004 V005 V006 V007 V008 V009 V010 V011 V012"
mkdir -p "$BASE"

[ -s "$BASE/matrix.csv" ] || echo "case_id,mta,version,policy,smtp_final_code,reject_node,raw_bytes,raw_sha256,header_section_bytes,header_end_offset,logical_header_count,received_exact,received_ci,from_in_header,to_in_header,subject_in_header,message_id_in_header,x_case_id_in_header,mime_error_in_header,malformed_in_header,received_in_body,normalized,notes" > "$BASE/matrix.csv"

g() { grep -oP "$1" "$2" 2>/dev/null | tail -1; }

# rejecting node = first node whose delta shows its own 554 (not an upstream bounce)
reject_node() {
    local i f
    for i in 1 2 3; do
        f="$1"; [ $i = 2 ] && f="$2"; [ $i = 3 ] && f="$3"
        if grep -q "status=bounced" "$f" 2>/dev/null; then continue; fi
        if grep -qE "hopcount exceeded|NOQUEUE.*554|cleanup.*554|mime-error" "$f" 2>/dev/null; then
            echo "postfix$i"; return
        fi
    done
    echo "-"
}

set_policy() { # $1: default|fix_quietly|add_header|reject  (PF11 chain only)
    for h in postfix1n postfix2n postfix3n; do
        if [ "$1" = default ]; then
            docker exec $h postconf -X non_empty_end_of_header_action 2>/dev/null
        else
            docker exec $h postconf -e "non_empty_end_of_header_action = $1"
        fi
        docker exec $h postfix reload >/dev/null 2>&1
    done
    sleep 1
}

run_round() { # ENV POLICY S1 N1 N2 N3 VERSION
    local ENV="$1" POLICY="$2" S1="$3" N1="$4" N2="$5" N3="$6" VER="$7"
    echo "===== round ENV=$ENV policy=$POLICY (postfix $VER via $S1) ====="
    docker exec mail-client python3 /scripts/check_delivery.py --clear >/dev/null

    local CASE D o1 o2 o3 code delivered bounce rn normalized notes
    for CASE in $CASES; do
        D="$BASE/$ENV/$POLICY/$CASE"
        mkdir -p "$D"
        cp "$BASE/corpus/$CASE.eml" "$D/input.eml"
        o1=$(docker logs $N1 2>&1 | wc -l)
        o2=$(docker logs $N2 2>&1 | wc -l)
        o3=$(docker logs $N3 2>&1 | wc -l)

        docker exec mail-client python3 /scripts/send_received.py \
            --server "$S1" --input-file "$CORPUS_IN/$CASE.eml" > "$D/$CASE.smtp.log" 2>&1
        code=$(g 'DATA_REPLY: \K[0-9]{3}' "$D/$CASE.smtp.log")

        docker logs $N1 2>&1 | tail -n +$((o1+1)) > "$D/p1.log"
        docker logs $N2 2>&1 | tail -n +$((o2+1)) > "$D/p2.log"
        docker logs $N3 2>&1 | tail -n +$((o3+1)) > "$D/p3.log"
        rn=$(reject_node "$D/p1.log" "$D/p2.log" "$D/p3.log")

        docker exec mail-client python3 /scripts/inspect_raw.py --case-id "$CASE" --timeout 10 \
            "${NAMES[@]}" --save "/results/phase3/$ENV/$POLICY/$CASE" > "$D/inspect.log" 2>&1
        delivered=$(g '^FOUND: \K\S+' "$D/inspect.log")
        docker exec mail-client python3 /scripts/check_delivery.py --case-id "$CASE" --timeout 6 \
            > "$D/check.log" 2>&1
        bounce=$(g '^BOUNCE: \K\S+' "$D/check.log")

        local raw_bytes sha hsb heo lh re rci mal rib
        raw_bytes=$(g '^RAW_BYTES: \K[0-9]+' "$D/inspect.log")
        sha=$(g '^RAW_SHA256: \K[0-9a-f]+' "$D/inspect.log")
        hsb=$(g '^HEADER_SECTION_BYTES: \K[0-9]+' "$D/inspect.log")
        heo=$(g '^HEADER_END_OFFSET: \K[0-9]+' "$D/inspect.log")
        lh=$(g '^LOGICAL_HEADERS: \K[0-9]+' "$D/inspect.log")
        re=$(g '^RECEIVED_EXACT: \K[0-9]+' "$D/inspect.log")
        rci=$(g '^RECEIVED_CI: \K[0-9]+' "$D/inspect.log")
        mal=$(g '^MALFORMED_IN_HEADER: \K[0-9]+' "$D/inspect.log")
        rib=$(g '^RECEIVED_IN_BODY: \K[0-9]+' "$D/inspect.log")
        local from_h to_h subj_h mid_h xch
        from_h=$(g '^NAME From: header=\K[0-9]+' "$D/inspect.log")
        to_h=$(g '^NAME To: header=\K[0-9]+' "$D/inspect.log")
        subj_h=$(g '^NAME Subject: header=\K[0-9]+' "$D/inspect.log")
        mid_h=$(g '^NAME Message-ID: header=\K[0-9]+' "$D/inspect.log")
        xch=$(g '^NAME X-Case-ID: header=\K[0-9]+' "$D/inspect.log")
        mime_err=$(g '^NAME MIME-Error: header=\K[0-9]+' "$D/inspect.log")

        normalized="-"
        if [ "$CASE" = V005 ] || [ "$CASE" = V006 ]; then
            if [ "$delivered" = yes ] && [ "${re:-0}" = 9 ]; then normalized=yes; else normalized=no; fi
        fi
        notes="$(g 'DATA_REPLY: \K.*' "$D/$CASE.smtp.log");bounce=${bounce:--}"

        echo "$CASE,postfix,$VER,$POLICY,$code,$rn,${raw_bytes:--},${sha:--},${hsb:--},${heo:--},${lh:--},${re:--},${rci:--},${from_h:--},${to_h:--},${subj_h:--},${mid_h:--},${xch:--},${mime_err:--},${mal:--},${rib:--},$normalized,\"$(csv_escape "$notes")\"" >> "$BASE/matrix.csv"

        printf '{"case":"%s","env":"%s","policy":"%s","version":"%s","smtp_final_code":"%s","reject_node":"%s","delivered":"%s","bounce":"%s","raw_sha256":"%s","received_exact":"%s","notes":"%s"}\n' \
            "$CASE" "$ENV" "$POLICY" "$VER" "${code:--}" "$rn" "${delivered:--}" "${bounce:--}" "${sha:--}" "${re:--}" "$(csv_escape "$notes")" \
            > "$D/result.json"

        echo "[$ENV/$POLICY/$CASE] code=${code:--} delivered=${delivered:--} reject=$rn rcv_exact=${re:--} rcv_body=${rib:--} from_h=${from_h:--} subj_h=${subj_h:--} mal_h=${mal:--} bounce=${bounce:--}"
    done
}

csv_escape() { local v="$1"; v="${v//,/;}"; printf '%s' "$v"; }

# corpus is deterministic; always (re)build so manifest matches bytes on disk
docker exec mail-client python3 /scripts/build_corpus.py --out "$CORPUS_IN"

ROUNDS="${*:-pf37 pf11}"
PF37_VER=$(docker exec postfix1 postconf -h mail_version)

for r in $ROUNDS; do
    case $r in
        pf37)
            run_round PF37 default postfix1 postfix1 postfix2 postfix3 "$PF37_VER"
            ;;
        pf11)
            PF11_VER=$(docker exec postfix1n postconf -h mail_version)
            SUP=$(docker exec postfix1n postconf -d non_empty_end_of_header_action 2>/dev/null | grep -c . || true)
            if [ "${SUP:-0}" = 0 ]; then
                echo "PF11 chain does not support non_empty_end_of_header_action; default round only"
                run_round PF11 default postfix1n postfix1n postfix2n postfix3n "$PF11_VER"
            else
                run_round PF11 default postfix1n postfix1n postfix2n postfix3n "$PF11_VER"
                set_policy fix_quietly
                run_round PF11 fix_quietly postfix1n postfix1n postfix2n postfix3n "$PF11_VER"
                set_policy add_header
                run_round PF11 add_header postfix1n postfix1n postfix2n postfix3n "$PF11_VER"
                set_policy reject
                run_round PF11 reject postfix1n postfix1n postfix2n postfix3n "$PF11_VER"
                set_policy default   # cleanup: remove override
            fi
            ;;
        *) echo "unknown round: $r"; exit 1 ;;
    esac
done

echo "phase3 done -> $BASE/matrix.csv"
