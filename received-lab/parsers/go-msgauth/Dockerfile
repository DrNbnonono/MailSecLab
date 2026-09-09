# K-series verifier: go-msgauth dkimverify (emersion, Go) built on Debian.
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && apt-get install -y golang-go ca-certificates && rm -rf /var/lib/apt/lists/*
# module fetch through the host proxy
ENV HTTPS_PROXY=http://172.29.112.1:17892 \
    HTTP_PROXY=http://172.29.112.1:17892 \
    GO111MODULE=on
RUN go install github.com/emersion/go-msgauth/cmd/dkim-verify@v0.6.8 \
 && ln -s /root/go/bin/dkim-verify /usr/local/bin/dkim-verify
CMD ["sleep", "infinity"]
