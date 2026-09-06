# F-series: Rspamd from Debian bookworm (same base as PF37), DNS-dependent
# checks disabled for a deterministic offline lab.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && apt-get install -y rspamd && rm -rf /var/lib/apt/lists/*
RUN for m in rbl surbl spf dmarc replies url_redirector attachments; do \
        printf 'enabled = false;\n' > /etc/rspamd/local.d/$m.conf; \
    done
CMD ["rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd"]
