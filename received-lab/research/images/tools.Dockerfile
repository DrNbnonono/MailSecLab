FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dkim=1.1.8-1 python3-dnspython openssl ca-certificates \
    libmail-dkim-perl golang-go dnsmasq-base rspamd redis-server \
    opendkim opendmarc dovecot-imapd dovecot-lmtpd curl dnsutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum* ./
COPY verify_go.go ./
RUN go mod tidy && go build -o /usr/local/bin/research-go verify_go.go \
    && go version -m /usr/local/bin/research-go > /usr/local/share/research-go-build.txt
WORKDIR /work
CMD ["sleep", "infinity"]
