FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    libmilter-dev libssl-dev libbsd-dev ca-certificates curl \
 && curl -fsSL -o /tmp/opendkim.orig.tar.gz \
    https://deb.debian.org/debian/pool/main/o/opendkim/opendkim_2.11.0~beta2.orig.tar.gz \
 && tar -xzf /tmp/opendkim.orig.tar.gz -C /tmp \
 && cd /tmp/OpenDKIM-rel-opendkim-2-11-0-Beta2 \
 && autoreconf -fi \
 && ./configure --prefix=/usr --sysconfdir=/etc \
 && make -j2 \
 && make install \
 && command -v opendkim \
 && opendkim -V \
 && rm -rf /tmp/opendkim-2.11.0~beta2 /tmp/opendkim.orig.tar.gz /var/lib/apt/lists/* \
 && id opendkim >/dev/null 2>&1 || useradd --system --home-dir /run/opendkim --shell /usr/sbin/nologin opendkim \
 && mkdir -p /run/opendkim \
 && chown opendkim:opendkim /run/opendkim
COPY opendkim.conf /etc/opendkim.conf
RUN chmod 644 /etc/opendkim.conf
CMD ["opendkim", "-f", "-x", "/etc/opendkim.conf"]
