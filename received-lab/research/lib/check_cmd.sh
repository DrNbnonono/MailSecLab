#!/bin/sh
docker exec msl-opendkim cat /proc/1/cmdline | tr '\0' ' '
echo
docker exec msl-opendkim cat /proc/1/status | head -8
