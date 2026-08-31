FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y \
        swaks \
        python3 \
        netcat-openbsd \
        curl \
        dnsutils \
        && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]