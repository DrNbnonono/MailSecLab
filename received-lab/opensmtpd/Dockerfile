# PF-B: OpenSMTPD from Debian bookworm (same pinned base as PF37).
# base digest was sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 (digest pin dropped: daemon cannot reach registries through current proxy)
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# local build workaround: reach apt via the host proxy (daemon egress is blocked)
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy

RUN apt-get update && \
    apt-get install -y opensmtpd rsyslog ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY smtpd.conf /etc/smtpd.conf
COPY smtpd.conf /etc/mail/smtpd.conf
COPY entrypoint.sh /entrypoint.sh

# Windows-mount build context: files appear 0777; enforce safe modes
RUN chmod 644 /etc/smtpd.conf /etc/mail/smtpd.conf && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
