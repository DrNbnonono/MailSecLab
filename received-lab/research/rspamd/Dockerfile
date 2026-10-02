FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends rspamd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY h_ip.lua /usr/share/rspamd/plugins/h_ip.lua
COPY local.d/ /etc/rspamd/local.d/
COPY modules.d/ /etc/rspamd/modules.d/
CMD ["rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd"]
