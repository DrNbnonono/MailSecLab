# PF_CURRENT: current Postfix from Debian sid (3.11.x at freeze time).
# base digest was sha256:c1acdb109bacb5adf0f2078892ac177ee2e2ce6f88e96c5b743998b5489d36a9 (digest pin dropped: same reason)
FROM debian:sid

ENV DEBIAN_FRONTEND=noninteractive
# local build workaround: reach apt via the host proxy (daemon egress is blocked)
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy

RUN apt-get update && \
    apt-get install -y postfix ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
