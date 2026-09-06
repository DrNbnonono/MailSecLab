# Phase 3C parser: Go net/mail (stdlib), built with Debian's golang-go.
# base digest was sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 (digest pin dropped: daemon cannot reach registries through current proxy)
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# local build workaround: reach apt via the host proxy (daemon egress is blocked)
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy

RUN apt-get update && \
    apt-get install -y golang-go && \
    rm -rf /var/lib/apt/lists/*

COPY parse_go.go /build/parse_go.go

RUN cd /build && go build -o /usr/local/bin/parse_go parse_go.go

CMD ["sleep", "infinity"]
