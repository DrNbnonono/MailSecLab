#!/bin/sh
set -eu
docker exec msl-auth-postfix postconf -e 'smtpd_milters = inet:msl-opendkim:8891, inet:msl-opendmarc:8893'
docker exec msl-auth-postfix postfix reload
docker exec msl-auth-postfix postconf smtpd_milters milter_default_action
docker exec msl-client python3 /opt/research/lib/chain_b.py
