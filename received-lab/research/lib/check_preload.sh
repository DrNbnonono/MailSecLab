#!/bin/sh
docker exec msl-opendkim id
docker exec msl-opendkim ls -l /usr/sbin/opendkim /usr/local/lib/dnsredir.so /proc/1/environ
docker exec msl-opendkim grep -a dnsredir /proc/1/maps || echo 'not mapped'
docker exec -u opendkim msl-opendkim cat /proc/1/environ | tr '\0' '\n' | grep PRELOAD || echo 'no preload env'
