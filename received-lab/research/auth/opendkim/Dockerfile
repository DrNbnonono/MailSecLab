FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends opendkim unbound gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/opendkim /usr/local/lib \
 && chown opendkim:opendkim /run/opendkim
COPY dnsredir.c /tmp/dnsredir.c
RUN gcc -shared -fPIC -o /usr/local/lib/dnsredir.so /tmp/dnsredir.c -ldl \
 && rm /tmp/dnsredir.c \
 && apt-get purge -y gcc libc6-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
COPY opendkim.conf /etc/opendkim.conf
COPY unbound.conf /etc/unbound/unbound.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 644 /etc/opendkim.conf /etc/unbound/unbound.conf /usr/local/lib/dnsredir.so \
 && chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
