#!/bin/sh
docker exec msl-opendkim grep -a -o 'sendmsg' /usr/lib/x86_64-linux-gnu/libunbound.so.8 | head
echo ====
docker exec msl-opendkim ls /evidence/w1-20261001a/clients/chain-b-fwd3
echo ==== calls
docker exec msl-opendkim wc -l /tmp/dnsredir-calls 2>/dev/null || echo no-calls
