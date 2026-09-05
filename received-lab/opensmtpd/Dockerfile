# PF-B: OpenSMTPD from Debian bookworm (same pinned base as PF37).
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y opensmtpd rsyslog ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY smtpd.conf /etc/smtpd.conf
COPY smtpd.conf /etc/mail/smtpd.conf
COPY entrypoint.sh /entrypoint.sh

# Windows-mount build context: files appear 0777; enforce safe modes
RUN chmod 644 /etc/smtpd.conf /etc/mail/smtpd.conf && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
