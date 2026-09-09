#!/bin/bash
# Build dnsmasq lab.test records from the mounted DKIM public key, then serve.
# NOTE: DNS TXT character-strings max 255 bytes; split p= accordingly (RFC 6376
# allows concatenation of multiple strings).
set -e
PUB=/results/j-series/dkim.pub.txt
CONF=/etc/dnsmasq.d/lab.conf
{
  printf 'txt-record=j1._domainkey.lab.test,"v=DKIM1; k=rsa; p='
  B64=$(cat $PUB | tr -d '\n')
  first=1
  while [ -n "${B64}" ]; do
    chunk=$(printf '%s' "$B64" | cut -c1-220)
    B64=$(printf '%s' "$B64" | cut -c221-)
    if [ $first = 1 ]; then printf '"%s"' "$chunk"; first=0
    else printf ' "%s"' "$chunk"; fi
  done
  printf '"\n'
  echo 'txt-record=lab.test,"v=spf1 -all"'
  echo 'txt-record=_dmarc.lab.test,"v=DMARC1; p=none; adkim=r; aspf=r"'
  echo "address=/mailpit.lab.test/172.31.0.7"
  echo "address=/postfix1.lab.test/172.31.0.16"
  echo "address=/client.lab.test/172.31.0.3"
  echo "no-resolv"
  echo "cache-size=0"
  echo "log-queries"
} > $CONF
exec dnsmasq --no-daemon --conf-file=$CONF
