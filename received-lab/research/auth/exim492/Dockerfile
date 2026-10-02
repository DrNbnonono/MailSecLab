FROM debian:buster-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'deb http://archive.debian.org/debian buster main\n\
deb http://archive.debian.org/debian buster-updates main\n\
deb http://archive.debian.org/debian-security buster/updates main\n' > /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check \
 && apt-get update \
 && apt-get install -y --no-install-recommends exim4-daemon-light ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY exim.conf /etc/exim/exim.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 644 /etc/exim/exim.conf && chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
