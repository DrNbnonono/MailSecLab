#!/bin/bash
set -e

postconf -e "myhostname = ${MYHOSTNAME}"
postconf -e "myorigin = \$myhostname"

postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"

postconf -e "mynetworks = 0.0.0.0/0"

postconf -e "mydestination ="

postconf -e "smtpd_relay_restrictions = permit_mynetworks,reject_unauth_destination"

postconf -e "smtp_tls_security_level = none"
postconf -e "smtpd_tls_security_level = none"

postconf -e "hopcount_limit = ${HOPCOUNT_LIMIT:-50}"

postconf -e "header_size_limit = ${HEADER_SIZE_LIMIT:-102400}"

if [ -n "${RELAYHOST}" ]; then
    postconf -e "relayhost = ${RELAYHOST}"
fi

# Debian postfix runs smtp/smtpd chrooted under /var/spool/postfix;
# resolver files must exist inside the chroot, otherwise relayhost
# names cannot be resolved via Docker DNS.
mkdir -p /var/spool/postfix/etc
cp -f /etc/resolv.conf /etc/hosts /etc/services /var/spool/postfix/etc/

# No syslog daemon in the container: send Postfix logging to stdout
# so that `docker logs` shows queue/delivery activity.
postconf -e "maillog_file = /dev/stdout"

echo "===================================="
echo "Postfix starting"
echo "Hostname:        ${MYHOSTNAME}"
echo "Relayhost:       ${RELAYHOST}"
echo "Hop count limit: ${HOPCOUNT_LIMIT:-50}"
echo "===================================="

postfix check

exec postfix start-fg