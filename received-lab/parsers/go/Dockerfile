# Phase 3C parser: Go net/mail (stdlib), built with Debian's golang-go.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y golang-go && \
    rm -rf /var/lib/apt/lists/*

COPY parse_go.go /build/parse_go.go

RUN cd /build && go build -o /usr/local/bin/parse_go parse_go.go

CMD ["sleep", "infinity"]
