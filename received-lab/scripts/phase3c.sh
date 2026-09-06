#!/bin/bash
# Phase 3C: feed the byte-fixed corpus to three independent MIME parsers
# (Python stdlib email, Node mailparser, Go net/mail) and record each parser's
# view. Output: results/phase3c/<CASE>.<parser>.json + parser_matrix.csv.
set -u
cd "$(dirname "$0")/.."
BASE=results/phase3c
CORPUS=/results/phase3/corpus
CASES="V001 V002 V003 V004 V005 V006 V007 V008 V009 V010 V011 V012"
mkdir -p "$BASE"

for CASE in $CASES; do
    F="$CORPUS/$CASE.eml"
    for P in python node go; do
        case $P in
            python) docker exec mail-client python3 /scripts/parse_python.py "$F" ;;
            node)   docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "$F" ;;
            go)     docker exec parser-go /usr/local/bin/parse_go "$F" ;;
        esac | sed "s/^{/{\"_case\":\"$CASE\",/" > "$BASE/$CASE.$P.json" 2>&1
        echo "[$CASE/$P] $(head -c 200 "$BASE/$CASE.$P.json")"
    done
done

docker exec mail-client python3 /scripts/build_parser_csv.py
echo "phase3c done -> $BASE/parser_matrix.csv"
