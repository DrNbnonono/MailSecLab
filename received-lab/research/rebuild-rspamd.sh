#!/bin/bash
set -eu
cd /mnt/e/MailSecLab/received-lab/research
export RUN_ID=w1-20261001a
docker compose -p mailseclab-research -f docker-compose.yml build rspamd
docker stop msl-dns msl-rspamd
