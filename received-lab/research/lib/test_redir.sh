#!/bin/sh
echo ==== entry
docker exec msl-opendkim cat /entrypoint.sh
echo ==== direct
docker exec msl-opendkim unbound-host -t TXT cal._domainkey.lab.test
echo ==== preload
docker exec -e LD_PRELOAD=/usr/local/lib/dnsredir.so msl-opendkim unbound-host -t TXT cal._domainkey.lab.test
echo ==== unbound log
docker exec msl-opendkim tail -20 /var/log/unbound.log
echo ==== dns log
docker logs --since 1m msl-dns 2>&1 | grep domainkey | tail -8
