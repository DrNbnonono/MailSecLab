#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
log() { echo "[$(date +%H:%M:%S)] $*"; }
log "== K0: start k1 stack (network recreate for static subnet) =="
docker compose --profile k1 down 2>&1 | tail -1
docker compose --profile k1 --profile frspamd --profile pf11 up -d 2>&1 | tail -1
sleep 5
log "== DNS check: j1._domainkey.lab.test TXT via dnsmasq =="
docker exec dns dnsmasq --test 2>&1 | head -1
docker run --rm --dns 172.30.0.53 --network received-lab_mailnet debian:bookworm-slim \
  sh -c 'apt-get slurp 2>/dev/null; which dig nslookup' 2>/dev/null | head -1
# busybox nslookup via alpine is easiest
docker run --rm --dns 172.30.0.53 --network received-lab_mailnet alpine sh -c \
  'nslookup -type=TXT j1._domainkey.lab.test 2>/dev/null | tail -4' 2>/dev/null || \
  log "(alpine not available locally; checking dnsmasq log instead)"
docker exec dns tail -5 /var/log/ 2>/dev/null
docker logs dns 2>&1 | tail -4
log "== smoke: go-msgauth dkim-verify usage =="
docker exec go-msgauth dkim-verify -h 2>&1 | head -6
log "== smoke: opendkim-testmsg usage =="
docker exec opendkim opendkim-testmsg -h 2>&1 | head -6
log "K0 DONE"
