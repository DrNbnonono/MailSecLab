#!/bin/sh
set -eu
pid=$(docker inspect -f '{{.State.Pid}}' msl-opendkim)
echo "pid $pid"
nsenter -t "$pid" -n iptables -t nat -C OUTPUT -p udp --dport 53 ! -d 10.88.0.53 -j DNAT --to-destination 10.88.0.53:53 2>/dev/null \
  || nsenter -t "$pid" -n iptables -t nat -A OUTPUT -p udp --dport 53 ! -d 10.88.0.53 -j DNAT --to-destination 10.88.0.53:53
nsenter -t "$pid" -n iptables -t nat -C OUTPUT -p tcp --dport 53 ! -d 10.88.0.53 -j DNAT --to-destination 10.88.0.53:53 2>/dev/null \
  || nsenter -t "$pid" -n iptables -t nat -A OUTPUT -p tcp --dport 53 ! -d 10.88.0.53 -j DNAT --to-destination 10.88.0.53:53
docker exec msl-client python3 /opt/research/lib/chain_b.py chain-b5
echo '=== queries'
docker logs --since 1m msl-dns 2>&1 | grep '10.88.0.41' | grep -v deb.debian | tail -15
echo '=== header'
docker exec msl-client python3 -c 'import pathlib; t=pathlib.Path("/evidence/w1-20261001a/clients/chain-b5/from-insert-before.stored.eml").read_text(errors="replace"); print("\n".join(t.splitlines()[:14]))'
