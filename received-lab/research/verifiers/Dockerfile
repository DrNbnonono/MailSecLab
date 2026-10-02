FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-setuptools python3-wheel \
      libmail-dkim-perl \
      golang-go git ca-certificates openssl dnsutils \
 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages 'dkimpy==1.1.8'
ENV GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct \
    CGO_ENABLED=0
RUN go install github.com/emersion/go-msgauth/cmd/dkim-verify@v0.6.8 \
 && ln -sf /root/go/bin/dkim-verify /usr/local/bin/dkim-verify
COPY verify_perl.pl /usr/local/bin/verify_perl.pl
RUN chmod 0755 /usr/local/bin/verify_perl.pl
CMD ["sleep", "infinity"]
