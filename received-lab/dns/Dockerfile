# K-series: lab.test authoritative DNS (dnsmasq). DKIM TXT record is built at
# container start from the mounted public key (results/j-series/dkim.pub.txt).
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && apt-get install -y dnsmasq && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
