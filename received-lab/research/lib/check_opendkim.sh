#!/bin/sh
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' msl-opendkim
echo ==== logs
docker logs --tail 50 msl-opendkim
echo ==== unbound
docker exec msl-opendkim tail -20 /var/log/unbound.log
