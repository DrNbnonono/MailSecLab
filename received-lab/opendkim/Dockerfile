# K-series verifier: OpenDKIM 2.11 (C, libopendkim) from Debian bookworm.
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && apt-get install -y opendkim opendkim-tools ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
