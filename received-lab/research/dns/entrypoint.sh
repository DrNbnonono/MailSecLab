#!/bin/bash
# Lab DNS for mailseclab-research. Serves only the records written here.
# DKIM TXT is built from the run directory public key; character-strings are
# split at 220 octets so each stays under the 255-octet DNS limit.
set -eu
RUN_ID="${RUN_ID:?RUN_ID is required}"
SELECTOR="${SELECTOR:-cal}"
PUB="/evidence/${RUN_ID}/keys/dkim.pub.b64"
CONF=/etc/dnsmasq.d/lab.conf
mkdir -p /etc/dnsmasq.d

{
  echo "listen-address=127.0.0.1"
  echo "listen-address=10.88.0.53"
  echo "bind-interfaces"
  echo "no-resolv"
  echo "no-hosts"
  echo "cache-size=0"
  echo "log-queries"
  echo "log-facility=-"
  echo "txt-record=lab.test,v=spf1 -all"
  echo "txt-record=_dmarc.lab.test,v=DMARC1; p=none; adkim=r; aspf=r"
  echo "address=/client.lab.test/10.88.0.11"
  echo "address=/postfix1.lab.test/10.88.0.21"
  echo "address=/postfix2.lab.test/10.88.0.22"
  echo "address=/postfix3.lab.test/10.88.0.23"
  echo "address=/mailpit.lab.test/10.88.0.25"
  echo "address=/rspamd.lab.test/10.88.0.30"
  echo "address=/postfix1/10.88.0.21"
  echo "address=/postfix2/10.88.0.22"
  echo "address=/postfix3/10.88.0.23"
  echo "address=/mailpit/10.88.0.25"
  echo "address=/client/10.88.0.11"
  echo "ptr-record=11.0.88.10.in-addr.arpa,client.lab.test"
  echo "ptr-record=21.0.88.10.in-addr.arpa,postfix1.lab.test"
  echo "ptr-record=22.0.88.10.in-addr.arpa,postfix2.lab.test"
  echo "ptr-record=23.0.88.10.in-addr.arpa,postfix3.lab.test"
  echo "ptr-record=25.0.88.10.in-addr.arpa,mailpit.lab.test"
  echo "ptr-record=30.0.88.10.in-addr.arpa,rspamd.lab.test"
  echo "ptr-record=53.0.88.10.in-addr.arpa,dns.lab.test"
} > "$CONF"

if [ -s "$PUB" ]; then
  b64=$(tr -d '\n\r' < "$PUB")
  rest="v=DKIM1; k=rsa; p=${b64}"
  {
    printf 'txt-record=%s._domainkey.lab.test' "$SELECTOR"
    while [ -n "$rest" ]; do
      chunk=$(printf '%s' "$rest" | cut -c1-220)
      rest=$(printf '%s' "$rest" | cut -c221-)
      printf ',"%s"' "$chunk"
    done
    printf '\n'
  } >> "$CONF"
  echo "DKIM TXT loaded selector=${SELECTOR} b64_len=${#b64}"
else
  echo "DKIM public key missing at ${PUB}; TXT for the selector is not published"
fi

EXTRA="/evidence/${RUN_ID}/keys/extra-dns.conf"
if [ -s "$EXTRA" ]; then
  cat "$EXTRA" >> "$CONF"
  echo "loaded extra DNS records from ${EXTRA}"
fi

exec dnsmasq --no-daemon --conf-file="$CONF"
