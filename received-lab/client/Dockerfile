FROM debian:bookworm-slim

RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && \
    apt-get install -y \
        swaks \
        python3 \
        python3-pip \
        openssl \
        netcat-openbsd \
        curl \
        dnsutils \
        && \
    rm -rf /var/lib/apt/lists/*
# J-series: real DKIM sign/verify (dkimpy); pypi via host proxy
RUN pip3 install --no-cache-dir --break-system-packages --proxy http://172.29.112.1:17892 dkimpy || \
    pip3 install --no-cache-dir --proxy http://172.29.112.1:17892 dkimpy

CMD ["sleep", "infinity"]
