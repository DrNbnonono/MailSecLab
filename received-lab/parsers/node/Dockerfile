# Phase 3C parser: Node.js + mailparser.
# base digest was sha256:c0753125a3789977aefe869cbebccf70e3cfd7ea84ca48547458f02e4f1d7146 (digest pin dropped: same reason)
FROM node:slim

WORKDIR /app
ENV npm_config_proxy=http://172.29.112.1:17892 npm_config_https_proxy=http://172.29.112.1:17892 npm_config_registry=https://registry.npmmirror.com
RUN npm install --no-audit --no-fund mailparser

CMD ["sleep", "infinity"]
