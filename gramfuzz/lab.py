"""MailSecLab 桥：独立工具引用实验室的共享设施与产物目录。

设计约束（为什么需要这一层）：
- 本仓库（E:\\Gramfuzz）只放工具；发送/捕获/证据设施（diffrun、tracefacts、
  evidence、smtp_send、目标容器配置）是实验室基础设施，单一事实来源在
  MailSecLab 的 received-lab/research/ 下，不复制进本仓库以免漂移。
- 运行产物（corpus、stage1/stage2、candidates.json）必须写到实验室的
  results/research/<run-id>/gramfuzz/——msl-client 等容器的 /evidence 挂载
  映射到那里，docker 侧探针靠这个路径读语料。
- lab_config.json 的 mailseclab_root 是 WSL 路径；本工具全部在 WSL 下运行。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parents[1]

_cfg = json.loads((TOOL_ROOT / "lab_config.json").read_text(encoding="utf-8"))
MAILSECLAB_ROOT = Path(_cfg["mailseclab_root"])

sys.path.insert(0, str(MAILSECLAB_ROOT))

from research.lib import diffrun  # noqa: E402
from research.lib.evidence import sha256_bytes  # noqa: E402
from research.lib.tracefacts import corpus_check, facts  # noqa: E402

RUN_ROOT = MAILSECLAB_ROOT / _cfg.get("run_root_relative", "results/research")
TARGETS_JSON = MAILSECLAB_ROOT / "research" / "diffrun-targets.json"
RFC_DIR = TOOL_ROOT / "rfc"
GRAMMAR_DIR = TOOL_ROOT / "grammar"
PARSERS_DIR = TOOL_ROOT / "parsers"
