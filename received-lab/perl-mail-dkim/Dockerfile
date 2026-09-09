# K-series verifier: Perl Mail::DKIM (CPAN-era, independent implementation).
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\nAcquire::https::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy
RUN apt-get update && apt-get install -y libmail-dkim-perl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY verify.pl /usr/local/bin/verify.pl
RUN chmod +x /usr/local/bin/verify.pl
CMD ["sleep", "infinity"]
