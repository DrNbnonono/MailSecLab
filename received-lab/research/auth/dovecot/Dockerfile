FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends dovecot-imapd dovecot-lmtpd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail \
 && useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail \
 && mkdir -p /var/mail && chown -R vmail:vmail /var/mail
COPY dovecot.conf /etc/dovecot/dovecot.conf
RUN chmod 644 /etc/dovecot/dovecot.conf
CMD ["dovecot", "-F"]
