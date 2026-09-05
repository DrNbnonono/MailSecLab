#!/bin/bash
# Phase 3B: run the byte-fixed corpus through alternative MTAs
# (Exim 4.96 and OpenSMTPD 6.8, single permissive smarthop -> mailpit).
# usage: phase3b.sh [rounds...]   rounds: exim opensmtpd (default both)
# Appends to the same results/phase3/matrix.csv (mta column distinguishes).
set -u
cd "$(dirname "$0")/.."
BASE=results/phase3
CORPUS_IN=/results/phase3/corpus
NAMES=(--name Received --name From --name To --name Subject --name Message-ID --name X-Case-ID --name MIME-Error)
CASES="V001 V002 V003 V004 V005 V006 V007 V008 V009 V010 V011 V012"
mkdir -p "$BASE"

[ -s "$BASE/matrix.csv" ] || echo "case_id,mta,version,policy,smtp_final_code,reject_node,raw_bytes,raw_sha256,header_section_bytes,header_end_offset,logical_header_count,received_exact,received_ci,from_in_header,to_in_header,subject_in_header,message_id_in_header,x_case_id_in_header,mime_error_in_header,malformed_in_header,received_in_body,normalized,notes" > "$BASE/matrix.csv"

g() { grep -oP "$1" "$2" 2>/dev/null | tail -1; }
csv_escape() { local v="$1"; v="${v//,/;}"; printf '%s' "$v"; }

# log offset helper per MTA
log_wc() { # $1 container $2 logfile
    docker exec "$1" sh -c "wc -l < $2 2>/dev/null" 2>/dev/null || echo 0
}
log_tail() { # $1 container $2 logfile $3 offset
    docker exec "$1" sh -c "tail -n +$(( $3 + 1 )) $2 2>/dev/null" 2>/dev/null
}

run_mta() { # ENV MTA SERVER VERSION LOGPATH
    local ENV="$1" MTA="$2" SERVER="$3" VER="$4" LOG="$5"
    echo "===== round ENV=$ENV (mta=$ENV/$VER via $SERVER) ====="
    docker exec mail-client python3 /scripts/check_delivery.py --clear >/dev/null

    local CASE D o code delivered bounce rn normalized notes
    for CASE in $CASES; do
        D="$BASE/$ENV/default/$CASE"
        mkdir -p "$D"
        cp "$BASE/corpus/$CASE.eml" "$D/input.eml"
        o=$(log_wc "$MTA" "$LOG")

        docker exec mail-client python3 /scripts/send_received.py \
            --server "$SERVER" --input-file "$CORPUS_IN/$CASE.eml" > "$D/$CASE.smtp.log" 2>&1
        code=$(g 'DATA_REPLY: \K[0-9]{3}' "$D/$CASE.smtp.log")

        log_tail "$MTA" "$LOG" "$o" > "$D/mta.log"

        docker exec mail-client python3 /scripts/inspect_raw.py --case-id "$CASE" --timeout 10 \
            "${NAMES[@]}" --save "/results/phase3/$ENV/default/$CASE" > "$D/inspect.log" 2>&1
        delivered=$(g '^FOUND: \K\S+' "$D/inspect.log")
        docker exec mail-client python3 /scripts/check_delivery.py --case-id "$CASE" --timeout 6 \
            > "$D/check.log" 2>&1
        bounce=$(g '^BOUNCE: \K\S+' "$D/check.log")

        local raw_bytes sha hsb heo lh re rci rws mal rib
        raw_bytes=$(g '^RAW_BYTES: \K[0-9]+' "$D/inspect.log")
        sha=$(g '^RAW_SHA256: \K[0-9a-f]+' "$D/inspect.log")
        hsb=$(g '^HEADER_SECTION_BYTES: \K[0-9]+' "$D/inspect.log")
        heo=$(g '^HEADER_END_OFFSET: \K[0-9]+' "$D/inspect.log")
        lh=$(g '^LOGICAL_HEADERS: \K[0-9]+' "$D/inspect.log")
        re=$(g '^RECEIVED_EXACT: \K[0-9]+' "$D/inspect.log")
        rci=$(g '^RECEIVED_CI: \K[0-9]+' "$D/inspect.log")
        rws=$(g '^RECEIVED_SPACE: \K[0-9]+' "$D/inspect.log")
        mal=$(g '^MALFORMED_IN_HEADER: \K[0-9]+' "$D/inspect.log")
        rib=$(g '^RECEIVED_IN_BODY: \K[0-9]+' "$D/inspect.log")
        local from_h to_h subj_h mid_h xch mime_err
        from_h=$(g '^NAME From: header=\K[0-9]+' "$D/inspect.log")
        to_h=$(g '^NAME To: header=\K[0-9]+' "$D/inspect.log")
        subj_h=$(g '^NAME Subject: header=\K[0-9]+' "$D/inspect.log")
        mid_h=$(g '^NAME Message-ID: header=\K[0-9]+' "$D/inspect.log")
        xch=$(g '^NAME X-Case-ID: header=\K[0-9]+' "$D/inspect.log")
        mime_err=$(g '^NAME MIME-Error: header=\K[0-9]+' "$D/inspect.log")

        rn="-"
        case ${code:--} in 5*) rn="$MTA" ;; esac
        normalized="-"
        if [ "$CASE" = V005 ] || [ "$CASE" = V006 ]; then
            if [ "$delivered" = yes ] && [ "${rws:--1}" = 0 ]; then normalized=yes; else normalized=no; fi
        fi
        notes="$(g 'DATA_REPLY: \K.*' "$D/$CASE.smtp.log");bounce=${bounce:--}"

        echo "$CASE,$ENV,$VER,default,$code,$rn,${raw_bytes:--},${sha:--},${hsb:--},${heo:--},${lh:--},${re:--},${rci:--},${from_h:--},${to_h:--},${subj_h:--},${mid_h:--},${xch:--},${mime_err:--},${mal:--},${rib:--},$normalized,\"$(csv_escape "$notes")\"" >> "$BASE/matrix.csv"

        printf '{"case":"%s","env":"%s","policy":"default","version":"%s","smtp_final_code":"%s","reject_node":"%s","delivered":"%s","bounce":"%s","raw_sha256":"%s","received_exact":"%s","notes":"%s"}\n' \
            "$CASE" "$ENV" "$VER" "${code:--}" "$rn" "${delivered:--}" "${bounce:--}" "${sha:--}" "${re:--}" "$(csv_escape "$notes")" \
            > "$D/result.json"

        echo "[$ENV/$CASE] code=${code:--} delivered=${delivered:--} reject=$rn rcv_exact=${re:--} rcv_ci=${rci:--} rcv_ws=${rws:--} rcv_body=${rib:--} from_h=${from_h:--} subj_h=${subj_h:--} bounce=${bounce:--}"
    done
}

EXIM_VER=$(docker exec exim sh -c '/usr/sbin/exim --version 2>&1 | head -1' | awk '{print $3}')
OSM_VER=$(docker exec opensmtpd sh -c '/usr/sbin/smtpd -h 2>&1' | head -1 | awk '{print $NF}')

ROUNDS="${*:-exim opensmtpd}"
for r in $ROUNDS; do
    case $r in
        exim)     run_mta EXIM exim exim "${EXIM_VER:-exim}" /var/log/exim4/main ;;
        opensmtpd) run_mta OSMTPD opensmtpd opensmtpd "${OSM_VER:-opensmtpd}" /var/log/syslog ;;
        *) echo "unknown round: $r"; exit 1 ;;
    esac
done

echo "phase3b done -> $BASE/matrix.csv"
