#!/bin/bash
# Experiment 3: real mail loop P1 -> P2 -> P3 -> P1 with hopcount_limit=8.
# Runtime-only config change; restores original topology via docker compose restart at the end.
set -u
cd "$(dirname "$0")/.."
mkdir -p results/loop

echo "== initial config =="
docker exec postfix1 postconf hopcount_limit relayhost
docker exec postfix2 postconf hopcount_limit relayhost
docker exec postfix3 postconf hopcount_limit relayhost

echo
echo "== applying loop topology: postfix3 relayhost -> [postfix1]:25, hopcount_limit=8 =="
for h in postfix1 postfix2 postfix3; do
    docker exec "$h" postconf -e "hopcount_limit = 8"
    docker exec "$h" postfix reload
done
docker exec postfix3 postconf -e "relayhost = [postfix1]:25"
docker exec postfix3 postfix reload
sleep 1

echo "== config now =="
docker exec postfix1 postconf hopcount_limit
docker exec postfix2 postconf hopcount_limit
docker exec postfix3 postconf hopcount_limit relayhost

o1=$(docker logs postfix1 2>&1 | wc -l)
o2=$(docker logs postfix2 2>&1 | wc -l)
o3=$(docker logs postfix3 2>&1 | wc -l)

echo
echo "== sending LOOP01 (N=0, normal message) =="
docker exec mail-client python3 /scripts/send_received.py -n 0 --case-id LOOP01 \
    | tee results/loop/LOOP01.smtp.log

echo "== waiting 25s for the loop to unwind =="
sleep 25

docker logs postfix1 2>&1 | tail -n +$((o1+1)) > results/loop/LOOP01.p1.log
docker logs postfix2 2>&1 | tail -n +$((o2+1)) > results/loop/LOOP01.p2.log
docker logs postfix3 2>&1 | tail -n +$((o3+1)) > results/loop/LOOP01.p3.log

echo "== mailpit side (should be empty: nothing ever reached mailpit) =="
docker exec mail-client python3 /scripts/check_delivery.py --case-id LOOP01 --timeout 3 || true

echo "== restore original topology (compose restart re-applies env config) =="
docker compose restart postfix1 postfix2 postfix3 >/dev/null
sleep 3
echo "== config after restore =="
docker exec postfix1 postconf hopcount_limit relayhost
docker exec postfix2 postconf hopcount_limit relayhost
docker exec postfix3 postconf hopcount_limit relayhost
echo "loop test done"
