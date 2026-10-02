#!/bin/sh
set -eu
postconf -e "myhostname = ${MYHOSTNAME}" "myorigin = lab.test" \
    'inet_interfaces = all' 'inet_protocols = ipv4' 'mydestination =' \
    'mynetworks = 127.0.0.0/8' 'relay_domains = lab.test, receiver.test, evil.test' \
    'smtpd_relay_restrictions = reject_unauth_destination' \
    'smtp_tls_security_level = none' 'smtpd_tls_security_level = none' \
    "hopcount_limit = ${HOPCOUNT_LIMIT:-50}" "header_size_limit = ${HEADER_SIZE_LIMIT:-102400}" \
    'message_size_limit = 20000000' 'maillog_file = /dev/stdout'
if [ -n "${RELAYHOST:-}" ]; then postconf -e "relayhost = ${RELAYHOST}"; fi
if [ -n "${MILTERS:-}" ]; then
    postconf -e "smtpd_milters = ${MILTERS}" 'milter_default_action = tempfail' 'milter_protocol = 6'
fi
if [ -n "${TRANSPORT:-}" ]; then
    postconf -e 'relayhost =' "transport_maps = static:${TRANSPORT}"
fi
mkdir -p /var/spool/postfix/etc
cp /etc/resolv.conf /etc/hosts /etc/services /var/spool/postfix/etc/
postfix check
exec postfix start-fg
