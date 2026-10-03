# 邮件语义差分收束计划（Diff Consolidation）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 w1/w2 已经产出但物理分散的差分实验收束为一个统一框架（一个事实 schema、一个 runner），补上少数真正还开着的实验缺口，同步 AGENTS.md 账本，并产出跨 run 综合文档。

**Architecture:** 不新建框架，而是合并已有的三份事实函数（`recfuzz.py`、`recfuzz2.py`、`osmtpd_loop.py`）为一个 stdlib-only 的 `tracefacts.py`（同一文件复制进 MailTrace 的 mailtrace-core，作为两个仓库之间的唯一契约），再以 `recfuzz2.py` 的发送/捕获循环为骨架泛化出 `diffrun.py`，挂进 `research/run.py` 现有的 stage 分发。所有 SMTP 发送仍走 `msl-client` + `smtp_send.py`，捕获仍走 Mailpit API，证据仍走 `/evidence` 绑定挂载 + SHA-256。

**Tech Stack:** Python 3.11（bookworm，msl-client 容器内）、Docker Compose 研究网（mailseclab-research-net）、pytest（`research/tests/`）、MailTrace 0.5（E:\MailTrace，Windows 侧 venv，仅任务 8）。

**工作目录：** WSL `/mnt/e/MailSecLab/received-lab`（实验与代码）；Windows `E:\MailSecLab`（计划文档与 AGENTS.md）；`E:\MailTrace`（仅任务 8）。

---

## 0. 现实基线（执行任何任务前必读）

本计划的输入分析（「TraceMiner 三级结构」）方向正确，但它的缺口清单相对仓库现状滞后：其中多数「P0/P1 缺口」在 w1-20261001a / w2-20261002a 已经关闭。**不要重做下列已关闭项。**

| 分析中的「缺口」 | 仓库现实 | 证据位置 |
| --- | --- | --- |
| P0：重跑 G4 | 已关闭。78 字节折行语料，N1/N50/N100 全投递，N100 存档 8,000,545 B、100 条 X-Received 无缺口；旧 9,096,191 B 数字作废 | `results/research/w1-20261001a/g4/`、w1 `RECORD.md` §G4 |
| P0：重做 I2 | 已关闭。自洽伪造链在文件扫描时把 rspamd source 指到伪造 from-clause（203.0.113.11）；过诚实中继后回到真实地址（10.88.0.23）；不自洽链被 join 检出 | `results/research/w1-20261001a/i2/`、`i2-rejected-header-order/`、`research/lib/i2_build.py` |
| P1：OpenSMTPD 同构环 | 已关闭。普通与 `Received :` 种子都在约 100 条普通 Received 处被 5.4.6 停住；空白变体不改写、只让历史行不计入，不破坏环路终止 | `results/research/w1-20261001a/osmtpd-loop/`、commit a902c92 |
| P1：DKIM 重复字段 first/last | 已关闭。perl/go 自底向上；dkimpy/rspamd 对第二 From 直接 fail；h= 重复（oversign）四家全 fail；实例绑定全景：DKIM/OpenDKIM=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部、SnappyMail=顶部 | `results/research/w1-20261001a/causal/`、`report/PAPER_SKELETON.md`、w2 `exec/imap-probe.json` |
| P2：自动最小化 | 已有一版。one-edit revert 验证（保持 DKIM-Signature 字节不变，回退单处编辑后分裂消失即最小） | `research/lib/minimize.py`、w1 `fuzz/minimized/` |
| P2：grammar 驱动 mutation | 部分已有。hdrfuzz2+ 的 enriched grammar + known-outcomes.json 去重 oracle（29 元组自动加载） | `research/lib/hdrfuzz2.py`、w2 `hdrfuzz2/known-outcomes.json` |
| P1：异构 MTA 矩阵 | 已有。repair_matrix（L1 framework from Forward Pass）：七个单跳性质过 Exim/OpenSMTPD 后 persist/break/created | `research/lib/repair_matrix.py`、w2 `repair/` |
| P3：Exim 4.92 对照 | 已做（仅作 I1 阳性对照） | w1 `exim492/` |

**真正还开着的缺口**（本计划的任务来源）：

1. recfuzz2 的 Exim 列 `captured=false`——250 接受后走默认路由进 auth-postfix 被 554，异步退信，转换事实没有捕获 → 任务 4。
2. parser 三家（python email / Go net/mail / Node mailparser）不在自动矩阵里，E3 的「严格 2 / Node 102」是手工测的 → 任务 5。
3. DKIM 验证器 × obs-colon Received 的交叉单元未填满（sig_probe 只做了 11 形态的存活轴） → 任务 6。
4. AGENTS.md 账本滞后：仍写着「未做 OpenSMTPD 同构环」「G4/I2 待补证」「DKIM first/last 不能下结论」，会误导任何基于它的人或 AI → 任务 1。
5. w2 两个在飞主攻面（Resent/Sender/Reply-To 身份轴、AR 形态轴）未收口；parsedmarc 离线装包受阻未记录 → 任务 2。
6. OpenDKIM 2.11.0 不向实验室 DNS 查公钥，实例绑定矩阵缺 OpenDKIM 列 → 任务 9（限时）。

---

## 任务 1：AGENTS.md 账本对齐（P0）

AGENTS.md 是本仓库的声明账本，它现在的「后续开发」和「不要写成定论」两节与现实相反。任何后续会话（包括 AI）都会被它误导——本计划的输入分析就是实例。

**Files:**
- Modify: `E:\MailSecLab\AGENTS.md`

- [ ] **Step 1.1：替换「后续开发」整节**

用下面的文本替换现有 `## 后续开发` 到下一节之间的全部内容：

```markdown
## 后续开发

1. ~~重跑 G4~~ 已关闭（w1）：`results/research/w1-20261001a/g4/`——78 字节折行语料，N1/N50/N100 全投递，N100 存档 8,000,545 B、100 条 X-Received 无缺口。旧 9,096,191 B 数字作废，不要再引用。
2. ~~重做 I2~~ 已关闭（w1）：`results/research/w1-20261001a/i2/`——自洽伪造链在文件扫描时确实把 rspamd source 指到伪造 from-clause；过诚实中继后回到真实会话地址；不自洽链被 join 检出（by-host ≠ from-host）。
3. ~~OpenSMTPD 同构环~~ 已关闭（w1）：`results/research/w1-20261001a/osmtpd-loop/`——普通与空白种子都在约 100 条普通 Received 处被 5.4.6 停住。空白变体保留原样、不计历史行，但中继自己新增的普通行仍计数，不破坏环路终止。
4. ~~DKIM 重复字段选择~~ 已关闭（w1 causal + w2 exec）：perl/go 自底向上取实例；dkimpy/rspamd 对第二实例 From 直接 fail；h= 重复列出（oversign）四家全 fail。实例绑定全景：DKIM/OpenDKIM=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部、SnappyMail=顶部。
5. ~~Exim 4.92 阳性对照~~ 已关闭（w1 `exim492/`）：CRLF 载荷 554 同步错误、LF 载荷注入留在单个正文，与 I1 修补版阴性一致。

当前真正开放的项目：

1. recfuzz2 的 Exim 捕获臂（250 后退信路径未捕获转换事实）。
2. parser 三家（Python/Go/Node）未进自动差分矩阵。
3. DKIM 验证器 × obs-colon Received 交叉单元。
4. OpenDKIM 2.11.0 不向实验室 DNS 查公钥（key not found），实例绑定矩阵缺该列。
5. parsedmarc 离线装包受阻——按 opendmarc-reports 缺 Switch.pm 的先例记录为工具缺口。
```

- [ ] **Step 1.2：修订「不要写成定论」节**

逐条处理：

- 删除「G4 的 9,096,191 B …不要引用这个字节数」条目，替换为：`- G4 已由 w1 重跑关闭；只引用 w1 的 8,000,545 B 折行语料数字。`
- 删除「I2 不能证明…」条目，替换为：`- I2 已由 w1 重做关闭；注意结论是双向的：自洽伪造链在无诚实中继时确实能主导 rspamd 文件扫描的 source，诚实中继之后恢复真实地址。`
- 删除「未做 OpenSMTPD 同构多跳或有限环…」条目，替换为：`- OpenSMTPD 同构环已做（w1）：空白变体不让真实环路越过 5.4.6。不要再写「未测环路」。`
- 删除「反转 From 后再签名…还不能单独证明」条目，替换为：`- DKIM 实例选择已有 causal 证据（perl/go 自底向上、dkimpy/rspamd 双实例 fail、oversign 全 fail）；OpenDKIM 列因公钥检索问题缺失，不要补写 OpenDKIM 的选择方向。`
- 追加一条：`- U-label 机制核心已被 CVE-2026-100891（2026-09-28）覆盖，本实验室为独立复现；增量（rua 报告空洞、NFD 阴性、显示层、服务端消费面）见 w2 UPSTREAM.md。不要写成全新漏洞。`
- 追加一条：`- w1/w2 的结论来自研究网栈（msl-auth-postfix/OpenDKIM/OpenDMARC/rspamd milter/Dovecot/Roundcube/SnappyMail/msl-dns），与默认三跳 Postfix 栈是两套环境，结论不要互相搬用。`

- [ ] **Step 1.3：在「已可引用的结果」节末尾追加**

```markdown
认证链与研究网（w1/w2，`received-lab/results/research/`）：

- OpenSMTPD 同构双中继环：普通与 `Received :` 种子都在约 100 条普通 Received 处被 5.4.6 停住（w1 `osmtpd-loop/`）。
- DKIM 实例选择：perl/go 自底向上，dkimpy/rspamd 双 From 即 fail，oversign 四家全 fail；From-above 突变体三跳 Postfix 后 perl/go 仍 pass 且投递，Roundcube 显示 Author、SnappyMail 显示 Attacker（w1 `causal/`、`report/PAPER_SKELETON.md`）。
- rspamd `get_from_ip()` 取顶部 Received 的 from-clause：自洽伪造链文件扫描时 source=伪造值，过诚实中继后恢复真实地址（w1 `i2/`）。
- OpenDMARC 1.4.2 不做 U-label→A-label 转换（RFC 9989 §5.3.1），原始 UTF-8 qname 永远 NXDOMAIN；同一信 OpenDMARC `dmarc=none` vs rspamd `DMARC_POLICY_REJECT`；执行翻转 550 vs 250；rua 聚合永远看不到 U-label 事件（w2 A 线）。核心已由 CVE-2026-100891 覆盖，增量见 w2 `UPSTREAM.md`。
- 显示层把 A-label/NFC/NFD 三种 From 全部渲染为受害者 Unicode 品牌（w2 `display/`，5 张截图）。
- repair matrix：七个单跳差分性质过 Exim/OpenSMTPD 中继后的 persist/break/created（w2 `repair/`）。
- recfuzz2：`Received` 八种语法形态 × 三 MTA，OpenSMTPD 对 `Received :`×55 保留 55 条、只计 2 条普通行仍 250 投递（w2 `recfuzz2/matrix.json`）。
```

- [ ] **Step 1.4：在「环境与操作」节的环境表后追加一行说明**

```markdown
第二套栈：研究网 `mailseclab-research-net`（msl-auth-postfix + OpenDKIM/OpenDMARC/rspamd milter + Dovecot + Roundcube/SnappyMail + msl-dns + msl-mailpit + Exim v3/OpenSMTPD），用于 w1/w2 认证链实验。当前栈状态与回滚表见 `received-lab/results/research/w2-20261002a/STATE.md`。
```

- [ ] **Step 1.5：验证**

Run: `grep -n "未做 OpenSMTPD\|9,096,191\|I2 不能证明" AGENTS.md`
Expected: 无输出（旧说法全部清除）。

- [ ] **Step 1.6：暂不提交**

AGENTS.md 的提交放在任务 2 的收尾 commit 里（见 Step 2.4），避免拆散。

---

## 任务 2：w2 在飞工作收尾与提交（P0）

**Files:**
- Modify: `received-lab/results/research/w2-20261002a/RECORD.md`、`STATE.md`、`LAB_JOURNAL.md`
- Create: 各收口实验的证据文件（在既有 `resent/`、`replyto/`、`arsurv/` 目录内补齐）

- [ ] **Step 2.1：核对两个在飞主攻面的记录状态**

Run（WSL）: `ls received-lab/results/research/w2-20261002a/resent/ received-lab/results/research/w2-20261002a/replyto/ received-lab/results/research/w2-20261002a/arsurv/` 并通读 `RECORD.md` 是否已有对应结论段。

结果目录已存在说明实验部分跑过。缺的只是 RECORD 固化段。每条结论补一行式记录：输入指针、SMTP 回复、存档指针、结论一句话。

- [ ] **Step 2.2：两个主攻面各给 ≤2 小时收口预算，跑不完就明确 parked**

用现有工具收口，不写新脚本：

- 身份字段轴：`research/lib/identity_fields.py` + `identity_imap.py`（Resent-\*/Sender/Reply-To）。
- AR 形态轴：`research/lib/ar_survival.py`（外域 authserv-id / obs 冒号 / 无 id / 折叠）。

超时未完成的，在 `STATE.md` 末尾追加 parked 条目，格式：`- parked：<假设>，已测 <哪些>，缺 <什么>，恢复条件 <一条>`。parked 不是失败，是预算边界。

- [ ] **Step 2.3：parsedmarc 工具缺口记录**

在 `RECORD.md` 的 ar 系列后追加：

```markdown
### parsedmarc 离线装包受阻（工具缺口）

容器无网，parsedmarc 及其依赖无法离线安装（同 opendmarc-reports 缺 Switch.pm 先例）。报告消费端验证未做，不影响数据级结论；如需复测，先准备离线 wheel 目录再挂载。
```

- [ ] **Step 2.4：分三个 commit 提交（不含用户自己的文献改名与旧计划删除）**

```bash
# commit 1：w2 日志与收口
git add received-lab/results/research/w2-20261002a/
git commit -m "记录 w2 身份字段与 AR 形态轴收口、parsedmarc 工具缺口"

# commit 2：recfuzz 两轮 + utf8env
git add received-lab/research/lib/recfuzz.py received-lab/research/lib/recfuzz2.py \
        received-lab/results/research/w2-20261002a/recfuzz received-lab/results/research/w2-20261002a/recfuzz2 \
        received-lab/results/research/w2-20261002a/utf8env
git commit -m "记录 recfuzz 两轮 Received 语法差分矩阵与 EAI 信封探针"

# commit 3：AGENTS.md 对齐（任务 1 产物）
git add AGENTS.md
git commit -m "更新 AGENTS.md：w1/w2 已关闭项与当前开放项对齐"
```

注意：`references/` 下的 PDF 改名、`docs/superpowers/plans/2026-10-01-mail-auth-research.md` 的删除是用户自己的整理，保持未提交，由用户自行处理（旧计划的规矩：不提交混有其他修改的 commit）。

- [ ] **Step 2.5：栈处置（重要时序）**

任务 4–6 需要研究网保持运行（msl-client、msl-mailpit、msl-auth-postfix、exim、opensmtpd、rspamd），且 WSL 保活任务 `exec_c1499e76` 在长实验期间继续保留。全部实验结束后的收尾动作（放在任务 7 之后）：

```bash
# 停保活 → 按 STATE.md 回滚表恢复默认栈（transport_maps 删除并 reload、exim 路由恢复、
# rspamd/opendmarc 配置复原）→ docker compose ps 核对
```

---

## 任务 3：tracefacts.py 统一事实层（P0）

三份重复的事实函数（`recfuzz.rec_facts`、`recfuzz2.rec_facts`、`osmtpd_loop.classify_header`）合并为一个 stdlib-only 模块。它同时是 MailTrace 侧的契约文件（任务 8），所以**不依赖 research 包内任何其他模块**。

**Files:**
- Create: `received-lab/research/lib/tracefacts.py`
- Test: `received-lab/research/tests/test_tracefacts.py`

- [ ] **Step 3.1：写失败测试**

```python
"""tracefacts 单测。合成语料锚定分类；recfuzz2 存档锚定计数。"""
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.tracefacts import (
    classify_received_line,
    corpus_check,
    facts,
)

STRICT = b"Received: from h1.lab.test by h2.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
OBS = b"Received : from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
OBS_TAB = b"Received\t: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CASE = b"rEcEiVeD: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CFWS = b"Received(Router): from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CFWS_INNER = b"Rece(c)ived: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
EIGHTBIT = "Rece\u00edved: from a.lab.test by b.lab.test".encode("utf-8")
NOCOLON = b"Received from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"


def build(*received, body=b"Please confirm.\r\n"):
    head = b"\r\n".join([b"From: a@lab.test", b"To: b@lab.test", *received])
    return head + b"\r\n\r\n" + body


def test_line_classes():
    assert classify_received_line(STRICT) == "strict"
    assert classify_received_line(OBS) == "obs-colon"
    assert classify_received_line(OBS_TAB) == "obs-colon"
    assert classify_received_line(CASE) == "case"
    assert classify_received_line(CFWS) == "cfws"
    assert classify_received_line(CFWS_INNER) == "cfws"
    assert classify_received_line(EIGHTBIT) == "eightbit-name"
    assert classify_received_line(NOCOLON) == "no-colon"
    assert classify_received_line(b"X-Other: no") is None
    assert classify_received_line(b" from continuation; line") is None


def test_eightbit_value_is_not_eightbit_name():
    line = "Received: from m\u00fcnchen.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000".encode("utf-8")
    assert classify_received_line(line) == "strict"


def test_obs_stack_counts_like_osmtpd_capture():
    relay = b"Received: from x.lab.test by opensmtpd.lab.test; Sat, 3 Oct 2026 21:00:00 +0000"
    f = facts(build(*([OBS] * 55), relay))
    assert f["received"]["obs-colon"] == 55
    assert f["received"]["strict"] == 1
    assert f["relay_added"] == 1


def test_zone_termination_is_visible():
    raw = (b"From: a@lab.test\r\n" + EIGHTBIT + b"\r\n\r\n"
           + b"To: b@lab.test\r\nSubject: sank\r\nbody\r\n")
    f = facts(raw)
    assert f["received"]["eightbit-name"] == 1
    assert f["body_headerish"] == 2


def test_double_crlf_artifact_is_flagged():
    # F1 教训：折行生成器在已有 CRLF 上再 join，头区在第一行就结束。
    raw = b"Received: a\r\n\r\nReceived: b\r\n\r\nFrom: a@lab.test\r\n\r\nbody\r\n"
    problems = corpus_check(raw)
    assert any("body" in p for p in problems)


def test_lf_corpus_facts():
    raw = b"From: a@lab.test\n" + OBS + b"\n\nbody\n"
    assert facts(raw)["received"]["obs-colon"] == 1


def test_recfuzz2_capture_anchor():
    from pathlib import Path

    import pytest

    p = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a/recfuzz2/v01-obs-colon-osmtpd.stored.raw")
    if not p.exists():
        pytest.skip("recfuzz2 存档不在本机")
    f = facts(p.read_bytes())
    assert f["received"]["obs-colon"] == 55
    assert f["received"]["strict"] == 2
```

- [ ] **Step 3.2：跑测试确认失败**

Run: `cd /mnt/e/MailSecLab/received-lab && python3 -m pytest research/tests/test_tracefacts.py -v`
Expected: FAIL（`ModuleNotFoundError: research.lib.tracefacts`）。

- [ ] **Step 3.3：实现 tracefacts.py**

```python
"""Canonical trace facts: byte-level Received classification in one schema.

同一个 facts dict 描述任何组件对同一字节做了什么：MTA 捕获、parser 目标、
验证器输入。差分 = 两个 facts dict 的差，而不是两个脚本的差。

本模块只用标准库、单文件：同一份文件复制进 MailTrace 的 mailtrace-core，
Windows 工作台与 WSL 实验室共用一个分类器（文件头保留 provenance 注释）。

互斥分类，每条头区物理行归且只归一类：
  strict        `Received:` —— RFC 5322，冒号紧贴字段名
  obs-colon     `Received :` / `Received<TAB>:` —— obs 语法，冒号前 WSP
  case          `rEcEiVeD:` / `RECEIVED:` —— 大小写变体（合法字段名）
  cfws          `Received(Router):` / `Rece(c)ived:` —— 字段名内注释
  eightbit-name `Receíved:` —— 字段名内非 ASCII 字节
  no-colon      `Received from ...` —— 该行永远成不了头字段

优先级：eightbit-name > cfws > no-colon > obs-colon > case > strict
（大小写与 obs 同时出现时记 case；语料中没有该组合，出现时再分家）。
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from collections import Counter

_WSP = b" \t"
_FIELDISH = re.compile(rb"^[!-9;-~]+:")
_RELAY_MARKERS = (
    b"by msl-auth-postfix", b"by auth-postfix", b"by exim", b"by opensmtpd",
    b"by msl-osloop", b"by msl-postfix",
)


def _strip_comments(head: bytes) -> bytes:
    out, depth = bytearray(), 0
    for b in head:
        if b == 0x28:  # (
            depth += 1
        elif b == 0x29:  # )
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(b)
    return bytes(out)


def classify_received_line(line: bytes) -> str | None:
    """对头区的一条物理行分类；不属于 Received 家族返回 None。"""
    colon = line.find(b":")
    head = line[:colon] if colon >= 0 else line[:80]
    ascii_fold = bytes(b for b in head.lower() if 0x20 <= b < 0x7F)
    folded = _strip_comments(ascii_fold).strip()
    if not folded.startswith(b"received"):
        return None
    if any(b > 0x7F for b in head):
        return "eightbit-name"
    if b"(" in head:
        return "cfws"
    rest = folded[len(b"received"):]
    if colon < 0 or rest:
        return "no-colon"
    if head == b"Received":
        return "strict"
    if head.rstrip(_WSP) == b"Received":
        return "obs-colon"
    return "case"


def split_zone(raw: bytes) -> tuple[list[bytes], bytes, int]:
    """在第一个头/体分隔符处切开。CRLF 与 bare-LF 并存时先出现者胜。
    返回 (头区物理行, 正文, 正文起始偏移)。"""
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf >= 0 and (lf < 0 or crlf <= lf):
        return raw[:crlf].split(b"\r\n"), raw[crlf + 4:], crlf + 4
    if lf >= 0:
        return raw[:lf].split(b"\n"), raw[lf + 2:], lf + 2
    sep = b"\r\n" if b"\r\n" in raw else b"\n"
    return raw.split(sep), b"", len(raw)


def facts(raw: bytes, relay_markers: Iterable[bytes] = ()) -> dict:
    """对一个观察点（输入语料或任一组件的输出字节）提取规范事实。"""
    zone_lines, body, zone_end = split_zone(raw)
    counts: Counter[str] = Counter()
    for line in zone_lines:
        if not line or line[:1] in _WSP:
            continue  # 折行 continuation 归属父行
        cls = classify_received_line(line)
        if cls is not None:
            counts[cls] += 1
    markers = tuple(relay_markers) or _RELAY_MARKERS
    body_lines = re.split(rb"\r\n|\n", body)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "total_bytes": len(raw),
        "zone_end": zone_end,
        "body_bytes": len(raw) - zone_end,
        "received": dict(counts),
        "received_zone_total": sum(counts.values()),
        "case_noncanonical": counts["case"],
        "relay_added": sum(1 for l in zone_lines if any(m in l for m in markers)),
        "no_colon_body": sum(1 for l in body_lines if classify_received_line(l) == "no-colon"),
        "body_headerish": sum(1 for l in body_lines[:50] if _FIELDISH.match(l)),
        "empty_zone_lines": sum(1 for l in zone_lines if not l),
    }


def corpus_check(raw: bytes) -> list[str]:
    """发送前结构自检（F1 教训的固化）。返回问题列表；空列表 = 干净。
    有意构造的 sink 语料会被标记——这是特性：预期中的问题必须显式承认。"""
    problems = []
    f = facts(raw)
    if f["empty_zone_lines"]:
        problems.append(f"{f['empty_zone_lines']} empty line(s) inside the header zone (double separator?)")
    if f["body_headerish"]:
        problems.append(f"{f['body_headerish']} header-like line(s) in the body (early zone end or sink)")
    if raw.count(b"\n") != raw.count(b"\r\n"):
        problems.append("bare LF present in a CRLF corpus")
    if f["zone_end"] >= len(raw):
        problems.append("no header/body separator found")
    return problems
```

- [ ] **Step 3.4：跑测试确认通过**

Run: `cd /mnt/e/MailSecLab/received-lab && python3 -m pytest research/tests/test_tracefacts.py -v`
Expected: 8 passed（若 `test_recfuzz2_capture_anchor` 因存档缺失 skip，也算通过；若断言失败，先核对 `recfuzz2/matrix.json` 的 v01-osmtpd 行，不要改断言迁就实现）。

- [ ] **Step 3.5：用 tracefacts 复核既有存档，做一次交叉验证**

```bash
python3 - <<'PY'
import sys
sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from pathlib import Path
from research.lib.tracefacts import facts
base = Path("results/research/w2-20261002a/recfuzz2")
for p in sorted(base.glob("*.stored.raw")):
    f = facts(p.read_bytes())
    print(p.name, f["received"], "relay:", f["relay_added"], "bodyish:", f["body_headerish"])
PY
```

Expected: v01-osmtpd 输出 `{'obs-colon': 55, 'strict': 2}`，与 `matrix.json` 的 `rec_obs=55, rec_exact=2` 一致。任何不一致都是 tracefacts 的 bug，修分类器而不是修存档。

- [ ] **Step 3.6：提交**

```bash
git add received-lab/research/lib/tracefacts.py received-lab/research/tests/test_tracefacts.py
git commit -m "加入 tracefacts：统一 Received 字节分类与语料结构自检"
```

---

## 任务 4：diffrun.py 统一差分 runner（P1）

以 `recfuzz2.py` 的发送/捕获循环为骨架，泛化为注册表驱动。补上 Exim 捕获臂是本任务的核心增量。

**Files:**
- Create: `received-lab/research/lib/diffrun.py`
- Create: `received-lab/research/diffrun-targets.json`（目标环境配置，执行时填）
- Modify: `received-lab/research/run.py`（注册 `diff` stage）
- Test: `received-lab/research/tests/test_diffrun_variants.py`

- [ ] **Step 4.1：前置环境手术——Exim 直连 Mailpit 捕获路由**

recfuzz2 里 Exim 列 `captured=false` 的根因：Exim 250 接受后按默认路由（`msl-auth-postfix:25`）转发，N=55 > postfix `hopcount_limit=50`，DATA 阶段 554，Exim 异步退信，Mailpit 里永远没有这封信。捕获臂必须让 Exim 直投 Mailpit：

```bash
# 1. 找到 exim 容器名与当前路由配置
docker ps --format '{{.Names}}\t{{.Image}}' | grep -i exim
EXIM=<容器名>
docker exec $EXIM sh -c 'grep -rn "msl-auth-postfix\|route_list\|smarthost" /etc/exim4/ 2>/dev/null | head'
# 2. 把出站路由从 msl-auth-postfix:25 改为 msl-mailpit:1025（只动 route 目标，别的不碰）
# 3. 重载并验证
docker exec $EXIM sh -c 'exim4 -bV >/dev/null 2>&1; pkill exim4 || true' # 按容器实际的服务方式重启
# 4. 控制信：N=1 严格 Received，rcpt=capture@lab.test，确认 Mailpit 收到且只有 exim 自己一条新增行
```

把容器名和改动写进 `diffrun-targets.json` 与 run 目录的 STATE 增量段（沿用 STATE.md 回滚表格式），跑完任务 6 后恢复。

- [ ] **Step 4.2：写 diffrun-targets.json 与失败测试**

`received-lab/research/diffrun-targets.json`：

```json
{
  "exim_container": "<Step 4.1 查到的名字>",
  "parse": {
    "python": {"container": "msl-client", "cmd": ["python3", "/opt/research/parsers/parse.py"]},
    "go": {"container": "<docker compose --profile parsers ps 查到>", "cmd": ["go", "run", "/work/parse.go"]},
    "node": {"container": "<同上>", "cmd": ["node", "/work/parse.js"]}
  }
}
```

`received-lab/research/tests/test_diffrun_variants.py`：

```python
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.diffrun import VARIANTS, build_raw, variant_name


def test_eight_variants_present():
    assert set(VARIANTS) == {
        "v00-plain", "v01-obs-colon", "v02-case", "v03-nocolon",
        "v04-8bit-name", "v05-cfws-name", "v06-comment-name", "v07-tab-name",
    }


def test_build_raw_shape_and_check():
    raw = build_raw(VARIANTS["v01-obs-colon"], n=3, case_id="t-obs-3")
    assert raw.count(b"\r\nReceived :") == 3
    assert b"X-Case-ID: t-obs-3" in raw
    head = raw.split(b"\r\n\r\n", 1)[0]
    assert not head.endswith(b"\r\n")  # 无双 CRLF 伪影


def test_variant_name_is_stable():
    assert variant_name("v01-obs-colon", "osmtpd", "capture") == "v01-obs-colon__osmtpd__capture"
```

- [ ] **Step 4.3：实现 diffrun.py**

```python
"""Unified differential runner: same bytes through every target, one schema.

合并 recfuzz.py / recfuzz2.py 的发送-捕获-计数循环。目标分三类：

  smtp:postfix / smtp:exim / smtp:osmtpd   经 msl-client 的 smtp_send.py 发送，
                                          存档字节从 Mailpit API 取（每个目标
                                          直投 Mailpit，存档即该 MTA 的输出）
  parse:python                             msl-client 内 python email (compat32)
  parse:go / parse:node                    parsers profile 容器，配置缺则拒跑

两个臂：threshold（N=55，看拒绝码）与 capture（N=25，低于所有阈值，看转换）。
行写入 <run>/diffrun/matrix.json；known.json 里已有的元组标 known=true，
重跑不把旧结果当新发现。事实一律来自 tracefacts.facts，本文件不再自写计数。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.evidence import sha256_bytes
from research.lib.tracefacts import corpus_check, facts as trace_facts

RUN_ROOT = Path("/mnt/e/MailSecLab/received-lab/results/research")
RESEARCH = Path("/mnt/e/MailSecLab/received-lab/research")
EVIDENCE_ROOT = "/evidence"

BASE = "Received: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000"
VARIANTS = {
    "v00-plain": BASE,
    "v01-obs-colon": "Received : from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v02-case": "rEcEiVeD: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v03-nocolon": "Received from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v04-8bit-name": "Rece\u00edved: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v05-cfws-name": "Received(Router): from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v06-comment-name": "Rece(c)ived: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v07-tab-name": "Received\t: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
}
N_THRESHOLD = 55
N_CAPTURE = 25

SMTP_TARGETS = {
    "postfix": ("msl-auth-postfix", 25),
    "osmtpd": ("opensmtpd", 25),
    # exim 的地址在启动时从 diffrun-targets.json 的容器名解析，不写死 IP。
}


def variant_name(variant: str, target: str, arm: str) -> str:
    return f"{variant}__{target}__{arm}"


def build_raw(template: str, n: int, case_id: str) -> bytes:
    head = "\r\n".join(
        template.format(n=i, n1=i + 1, ip=i % 200, mm=i % 60) for i in range(n)
    ).encode("utf-8")
    return (
        head + b"\r\n"
        + b"From: Bank Security <security@bank.test>\r\n"
        + b"To: bob@lab.test\r\n"
        + b"Date: Sat, 3 Oct 2026 23:30:00 +0000\r\n"
        + f"Subject: {case_id}\r\n".encode()
        + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
        + f"X-Case-ID: {case_id}\r\n".encode()
        + b"\r\nPlease confirm the payment.\r\n"
    )


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def container_ip(name: str) -> str:
    code, out, err = sh(["docker", "inspect", "-f",
                         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name])
    addr = out.strip()
    if code != 0 or not addr:
        raise RuntimeError(f"no IP for {name}: {err}——检查 diffrun-targets.json 的 exim_container")
    return addr


def load_config() -> tuple[dict, dict]:
    """读一次配置：SMTP 目标（exim 从容器名解析 IP，不写死）+ parse 目标。
    配置缺的目标直接不跑，不猜容器名。"""
    cfg_path = RESEARCH / "diffrun-targets.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    smtp = dict(SMTP_TARGETS)
    if cfg.get("exim_container"):
        smtp["exim"] = (container_ip(cfg["exim_container"]), 25)
    return smtp, cfg.get("parse", {})


FETCH_IN_CONTAINER = """
import json, sys, time, urllib.request
case_id, out_path = sys.argv[1], sys.argv[2]
for _ in range(10):
    try:
        r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=30", timeout=5)
        for msg in json.loads(r.read()).get("messages", []):
            if case_id in (msg.get("Subject") or ""):
                rid = msg["ID"]
                raw = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/message/%s/raw" % rid, timeout=5).read()
                open(out_path, "wb").write(raw)
                print("OK", len(raw)); sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
"""


def fetch_mailpit(case_id: str, container_rel_path: str, host_path: Path) -> bytes | None:
    for _ in range(3):
        code, out, _ = sh(
            ["docker", "exec", "-i", "msl-client", "python3", "-", case_id, container_rel_path],
            timeout=60, stdin=FETCH_IN_CONTAINER.encode(),
        )
        if out.strip().startswith("OK"):
            return host_path.read_bytes()
        time.sleep(1)
    return None


def smtp_arm(stage: Path, ev_stage: str, variant: str, target: str,
             server: str, port: int, n: int, arm: str) -> dict:
    case_id = variant_name(variant, target, arm)
    raw = build_raw(VARIANTS[variant], n=n, case_id=case_id)
    problems = corpus_check(raw)
    if problems:
        raise RuntimeError(f"{case_id}: corpus 自检未通过 {problems}")
    (stage / f"{case_id}.eml").write_bytes(raw)
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", server, "--port", str(port),
        "--mail-from", "alice@lab.test", "--rcpt-to", "capture@lab.test",
        "--input", f"{ev_stage}/{case_id}.eml",
        "--transcript", f"{ev_stage}/{case_id}.smtp.txt",
    ], timeout=90)
    try:
        sent = json.loads(out)
    except json.JSONDecodeError:
        sent = {"accepted": False, "raw": (out or err)[-300:]}
    stored = None
    if sent.get("accepted"):
        stored = fetch_mailpit(
            case_id, f"{ev_stage}/{case_id}.stored.raw", stage / f"{case_id}.stored.raw")
    return {
        "case": case_id, "variant": variant, "target": target, "arm": arm, "n": n,
        "smtp_code": (sent.get("reply") or "")[:3],
        "smtp": (sent.get("reply") or "")[:60],
        "captured": stored is not None,
        "facts": trace_facts(stored) if stored is not None else {},
        "input_sha256": sha256_bytes(raw),
    }


def parse_arm(stage: Path, variant: str, raw: bytes, target: str,
              container: str, cmd: list[str]) -> dict:
    case_id = variant_name(variant, target, "parse")
    (stage / f"{case_id}.eml").write_bytes(raw)
    code, out, err = sh(["docker", "exec", "-i", container, *cmd], timeout=60, stdin=raw)
    try:
        view = json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        view = {"error": (out or err)[-200:]}
    return {
        "case": case_id, "variant": variant, "target": target, "arm": "parse",
        "captured": True, "view": view,
        "input_sha256": sha256_bytes(raw),
    }


def known_key(row: dict) -> str:
    bucket = {k: row.get(k) for k in ("smtp_code", "captured")}
    if row.get("facts"):
        bucket["received"] = row["facts"]["received"]
    if row.get("view"):
        bucket["view_received"] = row["view"].get("received_count")
    return json.dumps([row["variant"], row["target"], row["arm"], bucket],
                      ensure_ascii=False, sort_keys=True)


def run_diff(run_id: str) -> dict:
    stage = RUN_ROOT / run_id / "diffrun"
    stage.mkdir(parents=True, exist_ok=True)
    ev_stage = f"{EVIDENCE_ROOT}/{run_id}/diffrun"
    targets, parse_cfg = load_config()
    known_path = stage / "known.json"
    known = set(json.loads(known_path.read_text(encoding="utf-8"))) if known_path.exists() else set()

    problems, rows = [], []
    for variant in VARIANTS:
        for target, (server, port) in targets.items():
            for arm, n in (("threshold", N_THRESHOLD), ("capture", N_CAPTURE)):
                try:
                    row = smtp_arm(stage, ev_stage, variant, target, server, port, n, arm)
                except Exception as exc:  # 仪器故障记问题，不静默
                    problems.append(f"{variant}/{target}/{arm}: {exc}")
                    continue
                key = known_key(row)
                row["known"] = key in known
                known.add(key)
                rows.append(row)
                print(json.dumps({k: row[k] for k in
                                  ("case", "smtp_code", "captured", "known")}), flush=True)
                time.sleep(0.8)
        raw_capture = build_raw(VARIANTS[variant], n=N_CAPTURE,
                                case_id=variant_name(variant, "corpus", "capture"))
        for target, spec in parse_cfg.items():
            row = parse_arm(stage, variant, raw_capture, target,
                            spec["container"], spec["cmd"])
            key = known_key(row)
            row["known"] = key in known
            known.add(key)
            rows.append(row)

    (stage / "matrix.json").write_text(
        json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    known_path.write_text(json.dumps(sorted(known), ensure_ascii=False, indent=1), encoding="utf-8")
    expected = len(VARIANTS) * (len(targets) * 2 + len(parse_cfg))
    if len(rows) != expected:
        problems.append(f"matrix 不完整：{len(rows)}/{expected}")
    return {"passed": not problems, "problems": problems}


if __name__ == "__main__":
    report = run_diff(sys.argv[1] if len(sys.argv) > 1 else "w3-20261003a")
    print("diff gate passed=", report["passed"])
    for p in report["problems"]:
        print(" -", p)
```

注意两个与 recfuzz2 不同的设计决定：发送前对语料跑 `corpus_check`，不干净直接拒绝（F1 教训固化）；`known.json` 使重跑不重复计数。

- [ ] **Step 4.4：把 diff stage 挂进 run.py**

`received-lab/research/run.py` 三处最小改动：

```python
from lib.diffrun import run_diff          # 与既有 lib 导入放一起
STAGES = ("bootstrap", "causal", "e2e", "fuzz", "defense", "report", "diff")
NEEDS["diff"] = ()                         # diff 无前置 gate：它自含控制与自检
runners = {"causal": run_causal, "e2e": run_e2e, "diff": run_diff}
```

- [ ] **Step 4.5：跑单测，再跑一次控制 case 验证仪器**

```bash
cd /mnt/e/MailSecLab/received-lab
python3 -m pytest research/tests/test_diffrun_variants.py -v
# 控制 case：只有 v00-plain，postfix+osmtpd 两目标（临时把 VARIANTS 裁剪或用小脚本调 smtp_arm）
```

控制 case 期望（全部已知结果，任何偏离先修仪器再跑矩阵）：

| case | 期望 |
| --- | --- |
| v00-plain threshold postfix | `554 5.4.0 too many hops` |
| v00-plain capture postfix (N=25) | 250，captured=true，strict=25+1 |
| v00-plain capture osmtpd (N=25) | 250，captured=true，strict=25+1 |
| v01-obs-colon capture osmtpd | 250，obs-colon=25，strict=1（OpenSMTPD 保留） |
| v01-obs-colon capture postfix | 250，strict=26（Postfix 规范化） |

- [ ] **Step 4.6：跑全矩阵并固化 RECORD**

```bash
python3 research/run.py --stage diff --run-id w3-20261003a
```

在 `results/research/w3-20261003a/diffrun/` 手写 `RECORD.md`：八形态 × 三 MTA × 两臂的结论表（只写与 recfuzz2 的差异和新信息：Exim 列的转换事实是全新数据），并把每列的事实表贴上。**Exim capture 列是本任务的新结果**——预期它像 OpenSMTPD 一样保留 obs 形态但计数（E3 旧结论），若不同立即记入「不要写成定论」。

- [ ] **Step 4.7：提交**

```bash
git add received-lab/research/lib/diffrun.py received-lab/research/run.py \
        received-lab/research/diffrun-targets.json \
        received-lab/research/tests/test_diffrun_variants.py \
        received-lab/results/research/w3-20261003a/diffrun
git commit -m "加入 diffrun 统一差分 runner，补 Exim 捕获臂与八形态矩阵"
```

---

## 任务 5：parser 三家接入（P1）

E3 的「严格解析、Python、Go 计 2 条，Node 计 102 条」是手工测的；本任务把它变成 diffrun 的常设目标列。

**Files:**
- Create: `received-lab/research/parsers/parse.py`、`parse.go`、`parse.js`（挂载进容器用）
- Modify: `received-lab/research/diffrun-targets.json`（填 parse 段）

- [ ] **Step 5.1：确认 parsers profile 容器与挂载**

```bash
cd /mnt/e/MailSecLab/received-lab
docker compose --profile parsers ps
# 记下 go 与 node 容器名；确认它们能否看到 /evidence 或 research/ 目录，
# 不能则用 docker cp 把三个 parse 脚本放进容器 /work/
```

- [ ] **Step 5.2：写三个 parser 探针（stdin 原始字节 → stdout 一行 JSON）**

`parse.py`（在 msl-client 内跑，bookworm python 3.11，与 e-series 同源）：

```python
import email, json, sys
raw = sys.stdin.buffer.read()
msg = email.message_from_bytes(raw)  # compat32 默认策略
print(json.dumps({
    "received_count": len(msg.get_all("Received") or []),
    "from_in_headers": msg.get("From") is not None,
    "defects": [type(d).__name__ for d in msg.defects],
}))
```

`parse.go`：

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
)

func main() {
	out := map[string]any{"received_count": 0, "from_in_headers": false, "error": ""}
	m, err := mail.ReadMessage(bufio.NewReader(os.Stdin))
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["received_count"] = len(m.Header["Received"])
		out["from_in_headers"] = m.Header.Get("From") != ""
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
```

`parse.js`：

```js
const simpleParser = require("mailparser").simpleParser;
(async () => {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  let out;
  try {
    const msg = await simpleParser(Buffer.concat(chunks));
    const rec = msg.headers.get("received");
    out = {
      received_count: rec == null ? 0 : Array.isArray(rec) ? rec.length : 1,
      from_in_headers: msg.headers.has("from"),
    };
  } catch (e) {
    out = { error: String(e) };
  }
  console.log(JSON.stringify(out));
})();
```

- [ ] **Step 5.3：控制 case 锚定后再跑全量**

控制期望（先验证，不符先修接线）：纯 obs-colon ×25 语料上 python=0、go=0、node=25（E3：mailparser 宽松计数 obs 行，python/go 只认严格形态）；v04-8bit-name 语料上 python 的 `from_in_headers=false`（V007：From 沉入正文），go/node 待测——这一格就是新数据。

```bash
python3 research/run.py --stage diff --run-id w3-20261003a   # parse 目标已在 targets 注册
```

- [ ] **Step 5.4：固化并提交**

RECORD 增补 parser 三列的 L1 表：八形态 × 三 parser 的 `received_count` 与 `from_in_headers`。v04/v06/v07 三行是全新数据点。

```bash
git add received-lab/research/parsers received-lab/research/diffrun-targets.json \
        received-lab/results/research/w3-20261003a/diffrun
git commit -m "接入 python/go/node parser 目标，L1 识别矩阵自动化"
```

---

## 任务 6：DKIM × obs-colon 签名轴交叉（P1）

sig_probe 已有「11 形态仅 obs-colon 存活」的签名轴结论；本任务补满 `{形态} × {中继} × {四验证器}` 的格子，把 L1 存活接到 L3 判定。

**Files:**
- Create: `received-lab/results/research/w3-20261003a/sigprobe2/matrix.csv` 与证据文件
- 复用: `research/lib/sign_cases.py`、`research/lib/verify_one.py`、`research/verifiers/`、`research/adapters/`

- [ ] **Step 6.1：构造三个签名基线（复用 w1 的 cal 密钥，d=lab.test）**

`h=from:to:subject:date:received`（received 必须进 h=，否则本问题不成立）：

1. `s0-strict-signed`：3 条严格 `Received:` 在签名时已存在。
2. `s1-obs-signed`：3 条 `Received :` 在签名时已存在。
3. `s2-obs-injected`：签 3 条严格行，签名后顶部再插 1 条 `Received :`。

- [ ] **Step 6.2：三个基线 × {无中继, osmtpd, postfix} × 四验证器（dkimpy / perl Mail::DKIM / go-msgauth / rspamd）**

全部走既有 `verify_one.py` 与 verifiers 适配器，不写新验证路径。中继后从 Mailpit 取存档再验（diffrun 的 fetch 复用）。

- [ ] **Step 6.3：锚定已知格，盯住新格**

已知锚：KB2 家族（签名后注入异常头 → dkimpy 拒解析、perl/go pass、rspamd R_DKIM_ALLOW）。新格：`s1-obs-signed` 四家的 pass/fail（签名时 obs 行已存在——dkimpy 能否对 obs 行做 relaxed 规范化？）与 `s2` 过 OpenSMTPD 后 obs 行保留时的四家结果（L1 保留是否把 dkimpy 的拒解析一路带进邮箱）。每个格子：输入 sha256、验证器 stdout、中继 transcript、存档指针。

- [ ] **Step 6.4：RECORD 固化 + AGENTS.md 增补一行结论 + 提交**

```bash
git add received-lab/results/research/w3-20261003a/sigprobe2
git commit -m "记录 DKIM 验证器 × obs-colon Received 交叉矩阵"
```

---

## 任务 7：跨 run 综合与论文骨架更新（P1）

**Files:**
- Create: `received-lab/results/research/SYNTHESIS.md`
- Modify: `received-lab/results/research/w1-20261001a/report/PAPER_SKELETON.md`

- [ ] **Step 7.1：写 SYNTHESIS.md 骨架（证据已核对过的填法）**

```markdown
# 跨 run 综合：邮件语义差分的三个层级

一句话：邮件的安全语义不是 message bytes 的唯一函数，而是 message × implementation 的函数。
四类语义角色（transport / parser / verifier / security & display consumer）对同一字节
各持一套 trace 与身份解释。

## L1 识别差分（同一字节里有哪些字段、边界在哪）
- Postfix：obs-colon 规范化并计数；大小写变体计数；8-bit 字段名终结头区（后续字段沉正文）。
- Exim：obs-colon 保留且计数（E3；diffrun capture 列复核）。
- OpenSMTPD：obs-colon 保留、不计入环路阈值（E3、recfuzz2、osmtpd-loop）。
- parser 三家：（diffrun parse 列——执行任务 5 后填数字）。
- 证据：w2 recfuzz2/matrix.json、w3 diffrun/matrix.json、E3 raw、V007。

## L2 解释差分（字段集合相同，恢复出的语义不同）
- 实例选择：DKIM/OpenDKIM=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部、SnappyMail=顶部。
- 身份归一化：OpenDMARC 不做 U→A 转换 vs rspamd 做（w2 A 线）。
- source 归因：rspamd get_from_ip() = 顶部 Received 的 from-clause（w1 i2）。
- 修复矩阵：七个单跳性质过异构中继后 persist/break/created（w2 repair/）。

## L3 决策差分（安全结论或结果翻转）
- 执行翻转：同一欺骗信 550（A-label）vs 250（U-label）（w2 eai-enforce）。
- 评估器分裂：OpenDMARC none vs rspamd REJECT，同一 qid（w2 exec z14/z15）。
- DKIM 判定分裂：perl/go pass vs dkimpy/rspamd fail（w1 causal；任务 6 的 obs 轴增补）。
- 监控空洞：rua 聚合永远不含 U-label 事件（w2 rua r1-r4）。
- 显示层分裂：Roundcube vs SnappyMail 对同一突变体显示不同发件人（w1 clients/）。
- 环路安全（阴性）：obs 变体不让真实环路越过 5.4.6（w1 osmtpd-loop）。

## 阴性结果表（攻击模型边界）
H 诚实中继恢复 source；I1 修补版走私阴性 + Exim 4.92 对照；NFD 不扩大 CVE-2026-100891；
ar1-3 伪造 AR 被剥离、Chen A4 fail-closed；环路 obs 安全。每条一行 + 证据指针。

## 与 CVE-2026-100891 的增量边界
见 w2 UPSTREAM.md；本文只引用不重述。
```

- [ ] **Step 7.2：更新 PAPER_SKELETON**

在「What this run supports」末尾追加 w1/w2 增量条目（U-label 评估器分裂与执行翻转、rua 空洞、显示层、repair matrix、recfuzz 语法矩阵），在「What it does not support」追加：无真实服务测量、OpenDKIM 列缺失、parsedmarc 未验证。

- [ ] **Step 7.3：披露决策清单（不发送）**

对两个候选（rspamd 群组/domain-literal DMARC 静默；外域 AR 存活 + SnappyMail 徽章）各写：证据链完整性检查表、上游检索记录（仿 CVE-2026-100891 的核查方式）、send/hold 建议。写入 `report/DISCLOSURE_DRAFT.md` 的候选区，`gate.json` 保持 `disclosure_sent: false`。

- [ ] **Step 7.4：栈回滚与收尾（任务 2 Step 2.5 的执行点）**

停保活任务 `exec_c1499e76`；按 w2 STATE.md 回滚表恢复默认栈（含任务 4 的 exim 路由恢复）；`docker compose ps` 核对；STATE.md 记录回滚完成。

- [ ] **Step 7.5：提交**

```bash
git add received-lab/results/research/SYNTHESIS.md \
        received-lab/results/research/w1-20261001a/report/
git commit -m "跨 run 三层级综合与论文骨架、披露候选更新"
```

---

## 任务 8：MailTrace 桥（P2）

**Files:**
- Create: `E:\MailTrace\packages\mailtrace-core\src\mailtrace_core\tracefacts.py`（任务 3 文件的副本）
- Create: `E:\MailTrace\packages\mailtrace-core\tests\test_tracefacts.py`（同一份测试，路径改 mailtrace_core）
- Modify: `E:\MailTrace\README.md`（一节「实验室矩阵导入」）

- [ ] **Step 8.1：复制 tracefacts + 测试进 mailtrace-core**

文件头追加一行 provenance：`# Copied from MailSecLab received-lab/research/lib/tracefacts.py @ <commit-sha>——两处修改必须同步`。测试里 `sys.path` 的插入与 `recfuzz2` 锚定用例改为 skip-if-absent。

- [ ] **Step 8.2：diffrun 增加 --corpus 模式（MailForge 输出直读）**

`diffrun.py` 加一个入口（约 15 行）：

```python
def corpus_files(corpus_dir: Path) -> list[Path]:
    """MailForge 归档或普通 .eml 目录。按文件名排序；manifest 存在时做
    sha256 交叉核对，普通目录也可用。"""
    return sorted(p for p in corpus_dir.iterdir() if p.suffix == ".eml")
```

Windows 侧生成：`.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\received-baseline.json --sweep .\experiments\cases\received-counts.json --store E:\MailTrace\output\w3-corpus`，WSL 侧以 `--corpus /mnt/e/MailTrace/output/w3-corpus` 消费同一批字节。MailForge 的 case 参数（`pre_colon_space`、`folding`、`newline`、`received_count`、`topology`）正好覆盖本计划的手写 VARIANTS 轴——长期看 VARIANTS 表由 forge sweep 取代，短期两者并存互相校验。

- [ ] **Step 8.3：README 增补一节并提交（MailTrace 仓库）**

说明：`local-experiments/` 归档与 `results/research/<run>/diffrun/matrix.json` 共用 tracefacts 语义，matrix.json 可作为实验输入在 Lab UI 复现。commit message：`bridge: shared tracefacts schema with received-lab diffrun`。

---

## 任务 9：OpenDKIM 公钥检索仪器修复（P2，限时 2 小时）

实例绑定矩阵缺 OpenDKIM 列的唯一原因：OpenDKIM 2.11.0 容器不向实验室 DNS 发 `cal._domainkey.lab.test` 查询（`dig` 直查正常、DNS 日志无该容器来源的查询、已试过本地转发器）。

- [ ] **Step 9.1：网络层定位（30 分钟）**

```bash
# 研究网内抓 UDP 53，确认查询是否根本没出容器
docker exec msl-client sh -c 'command -v tcpdump' || echo "无 tcpdump，改用 msl-dns 日志按 qname 匹配"
# 已有工具：research/lib/probe_opendkim_dns.sh、swap_opendkim_libc.sh、build_opendkim.sh
```

- [ ] **Step 9.2：修复或关闭（90 分钟上限）**

按 w1 已铺设的路径：`build_opendkim.sh` 重建镜像（resolver 路径）→ `swap_opendkim_libc.sh` 换 libc → 重跑一个已签名的正对照。2 小时内不通则写仪器缺口记录（同 parsedmarc 格式），OpenDKIM 列保持「缺列」，SYNTHESIS 不补写该列方向。

---

## 不做清单（本计划的负空间）

- 不开新主题：ARC、BIMI、S/MIME、更多 MIME、更多走私载荷——每一个都是独立坑，且与本计划的研究问题无关。
- 不再扫更大的 N：数量边界（F3）已闭合，边界是配置不是协议常数这一结论已足够。
- 不做真实服务测量（Gmail/Exchange 等），不出公网。
- 不重做已关闭项（见第 0 节表格）。
- `research/lib/` 不再新增一次性 `main()` 脚本——新目标一律进 diffrun 注册表；这是把「学生实验项目」变「测量系统」的机制本身。
- 未获用户明确授权不联系任何厂商、不公开发布；披露材料保持 unsent 草稿状态。

## 验收与停止规则

- 每个 matrix cell 留完整证据链：输入 `.eml` + sha256、SMTP transcript、存档 raw（或明确的 miss 原因）；定位邮件用 `X-Case-ID`，头区可能被终结的场景在整封 raw 里搜。
- 事实只能出自 `tracefacts.facts`；diffrun 或任何后续脚本里再出现手写 Received 计数即为缺陷。
- 控制case 期望不符 → 停下修仪器，不带着坏仪器跑矩阵；工具失败不记作阴性（沿用旧计划规则）。
- `known.json` 去重；重复样本不计独立发现；阴性结果照记。
- 每个任务完成 = 代码/证据 + RECORD/AGENTS.md 同步 + commit，三者缺一不算完成。
- 若任务 4–6 出现与既有结论矛盾的结果（例如 Exim 不再保留 obs 形态），先疑仪器（版本、路由、语料结构自检），复现两次后才改写结论，并在 AGENTS.md「不要写成定论」里留修正痕迹。

## 时间预算（单人）

| 任务 | 预算 |
| --- | --- |
| 1–2（账本 + 收尾提交） | 0.5 天 |
| 3（tracefacts） | 0.5 天 |
| 4（diffrun + Exim 臂） | 1 天 |
| 5（parser 三家） | 0.5 天 |
| 6（DKIM × obs） | 0.5 天 |
| 7（综合 + 论文骨架） | 1 天 |
| 8–9（桥 + 仪器，可选） | 各 0.5 天 |

关键路径：1→2→3→4→5→6→7；任务 8、9 可并行或推迟。
