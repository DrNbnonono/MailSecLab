#!/bin/bash
set -eu
cd /mnt/e/MailSecLab/received-lab
export PYTHONUNBUFFERED=1
python3 -c 'from research.lib.fuzz import run_fuzz; run_fuzz("w1-20261001a")'
python3 -c 'from research.lib.rest import run_rest; run_rest("w1-20261001a")'
