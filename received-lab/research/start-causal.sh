#!/bin/bash
set -eu
cd /mnt/e/MailSecLab/received-lab
export PYTHONUNBUFFERED=1
exec python3 research/run.py --stage causal --run-id w1-20261001a
