#!/bin/sh
set -eu
mkdir -p /etc/rspamd/local.d /var/lib/rspamd
for module in rbl surbl replies url_redirector attachments fuzzy_check neural; do
    printf 'enabled = false;\n' > /etc/rspamd/local.d/$module.conf
done
printf 'servers = "127.0.0.1:6379";\n' > /etc/rspamd/local.d/redis.conf
printf 'enabled = false;\n' > /etc/rspamd/local.d/greylist.conf
printf 'enabled = false;\n' > /etc/rspamd/local.d/ratelimit.conf
printf 'check_local = true;\ncheck_authed = true;\n' > /etc/rspamd/local.d/dkim.conf
printf 'check_local = true;\ncheck_authed = true;\n' > /etc/rspamd/local.d/spf.conf
printf 'actions { reject = "reject"; }\n' > /etc/rspamd/local.d/dmarc.conf
printf 'bind_socket = "0.0.0.0:11333";\n' > /etc/rspamd/local.d/worker-normal.inc
printf 'bind_socket = "0.0.0.0:11334";\n' > /etc/rspamd/local.d/worker-controller.inc
printf 'bind_socket = "0.0.0.0:11332";\nmilter = yes;\ntimeout = 30s;\nupstream "local" { default = yes; self_scan = yes; }\n' > /etc/rspamd/local.d/worker-proxy.inc
printf 'extended_spam_headers = true;\nskip_local = false;\nskip_authenticated = false;\nuse = ["authentication-results", "x-spamd-result"];\n' > /etc/rspamd/local.d/milter_headers.conf
printf 'dns { nameserver = ["172.28.0.53"]; timeout = 1s; retransmits = 1; }\n' > /etc/rspamd/local.d/options.inc
chown -R _rspamd:_rspamd /var/lib/rspamd
redis-server --daemonize yes --bind 127.0.0.1
rspamd -t
exec rspamd -f -u _rspamd -g _rspamd
