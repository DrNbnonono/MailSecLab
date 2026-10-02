#!/bin/sh
echo '=== ldd'
docker exec msl-opendkim ldd /usr/sbin/opendkim | grep -E 'unbound|resolv|dns'
echo '=== dig via opendkim netns'
docker run --rm --network container:msl-opendkim --entrypoint dig mailseclab-research-dns @10.88.0.53 cal._domainkey.lab.test TXT +short +time=2 +tries=1
echo '=== dig via docker resolver in that netns'
docker run --rm --network container:msl-opendkim --entrypoint dig mailseclab-research-dns @127.0.0.11 cal._domainkey.lab.test TXT +short +time=2 +tries=1
