#!/bin/bash
# K3 canary: is rspamd 3.4 exit-255 caused by maps.rspamd.com refresh?
# Point maps.rspamd.com at 127.0.0.1 (instant refusal instead of hang) with
# network ENABLED; if stable for 5 min, the hang->crash theory holds.
set -u
cd /mnt/e/MailSecLab/received-lab
docker rm -f rs-canary >/dev/null 2>&1
docker run -d --name rs-canary --network received-lab_mailnet \
  --add-host maps.rspamd.com:127.0.0.1 \
  received-lab-rspamd bash -c 'printf "level = \"info\";\ntype = \"stderr\";\n" > /etc/rspamd/local.d/logging.inc; exec rspamd -f -u _rspamd -g _rspamd' >/dev/null
sleep 10
up=0
for i in $(seq 1 30); do
  st=$(docker inspect rs-canary --format '{{.State.Status}}' 2>/dev/null)
  [ "$st" != "running" ] && break
  sleep 10
  up=$((up+10))
  echo "  canary alive at ${up}s"
done
st=$(docker inspect rs-canary --format '{{.State.Status}} exit={{.State.ExitCode}}' 2>/dev/null)
echo "CANARY-RESULT: $st after ${up}s"
if [ "$st" = "running" ]; then echo "CANARY: STABLE with instant-refused maps -> hang theory holds"; else echo "CANARY: still crashes"; docker logs rs-canary 2>&1 | tail -5; fi
