#!/bin/bash
docker compose --profile k1 up -d >/dev/null 2>&1; sleep 2
echo "-- plain:"; docker exec opendkim sh -c 'opendkim-testmsg < /results/k-series/KB1-clean.signed.eml' 2>&1 | tail -1
echo "-- with -C:"; docker exec opendkim sh -c 'opendkim-testmsg -C < /results/k-series/KB1-clean.signed.eml' 2>&1 | tail -1
echo "-- od output full (plain):"; docker exec opendkim sh -c 'opendkim-testmsg < /results/k-series/KB1-clean.signed.eml' 2>&1
echo "-- hexdump tail of file:"; docker exec opendkim sh -c 'tail -c 24 /results/k-series/KB1-clean.signed.eml | od -c' | head -3
