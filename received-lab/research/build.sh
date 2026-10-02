#!/bin/bash
set -euo pipefail
cd /mnt/e/MailSecLab/received-lab
mkdir -p research/.state
docker build --network host -f research/images/tools.Dockerfile -t mailseclab-research-tools:bookworm research/images
