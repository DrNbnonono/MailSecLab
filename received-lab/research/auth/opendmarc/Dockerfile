FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends opendmarc publicsuffix \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/opendmarc && chown opendmarc:opendmarc /run/opendmarc
COPY opendmarc.conf /etc/opendmarc.conf
RUN chmod 644 /etc/opendmarc.conf
CMD ["opendmarc", "-f", "-c", "/etc/opendmarc.conf"]
