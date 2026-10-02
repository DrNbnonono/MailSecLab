#!/bin/bash
set -eu
cd /mnt/e/MailSecLab/received-lab
python3 research/reset_partial.py
export PYTHONUNBUFFERED=1
exec python3 research/run.py --stage bootstrap --run-id w1-20261001a
