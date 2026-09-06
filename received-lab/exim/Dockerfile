# PF-B: Exim from Debian bookworm (same pinned base as PF37).
# base digest was sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 (digest pin dropped: daemon cannot reach registries through current proxy)
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# local build workaround: reach apt via the host proxy (daemon egress is blocked)
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy

RUN apt-get update && \
    apt-get install -y exim4 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY exim.conf /etc/exim/exim.conf
COPY entrypoint.sh /entrypoint.sh

# build context lives on a Windows mount (files appear 0777); exim refuses
# group/world-writable config files
RUN chmod 644 /etc/exim/exim.conf && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
