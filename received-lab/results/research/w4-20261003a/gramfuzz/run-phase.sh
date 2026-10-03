#!/bin/bash
# 后台起一个 funnel phase（nohup + phase.log，任务 7 长跑纪律），打印 pid。
# 用法: run-phase.sh <run_id> <phase> [额外 CLI 参数...]
RUN_ID="$1"; PHASE="$2"; shift 2
STAGE="/mnt/e/MailSecLab/received-lab/results/research/$RUN_ID/gramfuzz"
LOG="$STAGE/$PHASE.phase.log"
cd /mnt/e/Gramfuzz || exit 1
nohup python3 -m gramfuzz.funnel "$RUN_ID" --phase "$PHASE" "$@" > "$LOG" 2>&1 &
echo "$PHASE started pid $! log $LOG"
