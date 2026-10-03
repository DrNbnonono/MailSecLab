# Gramfuzz —— IMF 顶层头语法差分模糊测试引擎

对 RFC 5321/5322（含 obs 语法）、8601（Authentication-Results）、6376（DKIM-Signature）、8617（ARC）、6532（EAI）、2045（MIME 参数文法，被 8601 引用）的顶层邮件头做 **ABNF 语法驱动的生成 + 变异 + 多实现差分**。

四层结构：

| 层 | 文件 | 职责 |
| --- | --- | --- |
| 提取器 | `gramfuzz/abnf.py` | RFC 规则文本 → 可执行文法（支持 `=/`、`:=`、RFC 7405 `%s/%i` 字面量） |
| 生成器 | `gramfuzz/gramgen.py` | 入口符号派生样本（RFC 5234 核心规则自动补齐、跨进程可复现种子） |
| 变异器 | `gramfuzz/grammut.py` | 字节/行/引导算子 + MIMEminer 式优先级反馈 |
| 漏斗 | `gramfuzz/funnel.py` | corpus → stage1（三 parser 批量差分）→ stage2（中继/签名/消费）→ candidates |

入口配置 `grammar/entries.json`（14 个入口），RFC 文本在 `rfc/`，批量探针在 `parsers/`，完整实施计划在 `docs/PLAN-gramfuzz.md`。

## 与 MailSecLab 的关系（必读）

本仓库**只有工具**。它依赖 MailSecLab（`E:\MailSecLab`）提供：

1. **共享设施**（经 `gramfuzz/lab.py` 桥接导入，不复制）：`research/lib/diffrun.py`（SMTP 发送/Mailpit 捕获/目标配置）、`research/lib/tracefacts.py`（规范事实）、`research/lib/evidence.py`（SHA-256）、签名与验证工具（`sign_cases.py`、`verify_one.py`）。
2. **目标环境**：Docker 研究网（msl-auth-postfix / exim / opensmtpd / msl-mailpit / msl-client / msl-verifiers / parser-node），容器名配置在实验室的 `research/diffrun-targets.json`。
3. **运行产物目录**：所有 run 写到实验室 `received-lab/results/research/<run-id>/gramfuzz/`——msl-client 的 `/evidence` 挂载映射到那里，docker 侧探针按这个路径读语料。

路径经 `lab_config.json` 配置（WSL 路径）。**本工具全部在 WSL 下运行。**

## 运行

```bash
# WSL，实验室栈在运行（msl-client / msl-mailpit / 三台 MTA / parser 容器）
cd /mnt/e/Gramfuzz
python3 -m pytest tests/ -v                        # 单测（不需要 docker）

RUN=w4-YYYYMMDDa
python3 -m gramfuzz.funnel $RUN --phase corpus     # 生成语料（fresh + mutated）
python3 -m gramfuzz.funnel $RUN --phase stage1     # 三 parser 批量差分 → survivors.json
python3 -m gramfuzz.funnel $RUN --phase stage2     # 幸存者过中继/签名/消费三臂
python3 -m gramfuzz.funnel $RUN --phase report     # candidates.json（4-5 号工作的门）
```

语料规模：`gramfuzz/funnel.py` 的 `FRESH_PER_ENTRY` / `MUTATED_PER_ENTRY`（全量默认 1500/1500，试跑可调小）。

## 纪律（继承自实验室）

- 发送前结构自检（tracefacts.corpus_check，F1 教训）；定位用 `X-Case-ID`。
- 校准锚：stage-1 必须先过 w3 六锚（v00/v02 一致，v01/v03/v04/v07 不一致）再跑批量。
- `candidates.json` 是真实服务验证与披露（4-5 号工作）的唯一决策门；本工具不做任何对外动作。

## 溯源

2026-10-03 自 MailSecLab `tool/gramfuzz` 分支迁出（迁出前提交 72cd0e0…f40914b，旧历史保存在 MailSecLab 本地 tag `gramfuzz-pre-split`）。实施计划的完整上下文（GAP1 调研、SIPCHIMERA/MIMEminer 方法论映射）见 `docs/PLAN-gramfuzz.md` 与 MailSecLab `results/research/GAP1-SURVEY-20261003.md`。
