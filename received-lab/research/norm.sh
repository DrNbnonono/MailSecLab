#!/bin/bash
set -eu
cd /mnt/e/MailSecLab/received-lab
find research -type f -exec sed -i 's/\r$//' {} +
python3 -m py_compile research/run.py research/lib/*.py
python3 research/lib/selftest_fold.py
