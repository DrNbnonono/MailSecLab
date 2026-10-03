# Gap 1 漏洞产出放大计划（Vuln Amplify）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 w4 的 150 条差分候选系统性转化为可披露的漏洞清单（目标 19+，对齐 MIMEminer 的厂商确认量级），并通过目标扩展、语法加深与组合变异持续放大产出——全部在实验室环境内完成，披露批次（Phase 4）由负责人开闸。

**Architecture:** 三道转化工序（聚类→最小化→规范符合性过滤）把「差分池」变成「违规池」；两台放大器（存量语料重放 + 新目标适配器）不重新生成就扩大差分面；一轮加深 campaign（组合变异 + 反馈权重）产出新池子。所有新代码进 E:\Gramfuzz（工具）或以分析产物形式进 MailSecLab（results/research/w5-*）。

**Tech Stack:** 既有 gramfuzz 四层引擎 + diffrun 目标注册表；新增目标（eml_parser / ruby mail / Haraka / 可选 mailparse-rs、neomutt）需要一次性安装（拉镜像/装包，与下载 RFC 同性质的 setup 网络行为，实验本身不出公网）；规范符合性分析用 RFC 文本抽取 + 人工判定。

**工作目录：** 工具改动在 E:\Gramfuzz（WSL /mnt/e/Gramfuzz）；分析产物在 MailSecLab `received-lab/results/research/w5-<执行日期>a/`；计划文档在 MailSecLab。

---

## 0. 从前人工作吸取的经验 → 我们的机制（本计划的设计依据）

| 前人经验 | 出处 | 我们的对应机制 |
| --- | --- | --- |
| 「检测器/客户端大量复用底层库，库级差分预示产品差分」 | MIMEminer §4.3 样本过滤的动机 | 目标扩展优先加**库**（eml_parser、ruby mail、mailparse-rs），而非整机产品 |
| 两阶段漏斗：本地库先差分、贵的真实产品只见过滤后的样本 | MIMEminer（5000→237→180） | 已有（39k→10k→236）；本计划复用**同一语料**打新目标（零生成成本） |
| 原始命中要**聚类成方法类**才有「19 条」这个数 | MIMEminer（180 个绕过 → 19 类方法） | 任务 A1：150 候选 → 机制家族（预期 20–40 族） |
| 差分 → 可利用的**分诊漏斗**（448 差分 → 15 根因 → 3 可利用） | Andarzian §VIII–IX | 任务 A3：差分 → RFC 违规 → 可披露 三级分诊 |
| 语法生成 + 变异 + **反馈调度**（RL/权重） | ReqsMiner、MIMEminer §4.3 反馈 | 任务 C3：把 w4 的 by_op 幸存率喂回 PriorityTable 作 w5 初始权重 |
| Validator 以**最终用户看到的**为判据（消息出现在被冒充者名下） | SIPCHIMERA §IV-E | 任务 D：每族一条后果陈述（徽章/身份/判决/投递），含证据 |
| 攻击系列字母表 + trust/parse 根因分类 | SIPCHIMERA A/B/C/D | 已有 P/T/X/D + 四根因（TAXONOMY）；新家族接续编号 |
| 「组合杀人」：单家可辩护、组合致命——但厂商计数来自**服务商广度** | Chen 2020（10 家服务商 → 18 类） | 我们的开源厂商面 ≈ 10 家（rspamd/dkimpy/SnappyMail/OpenDMARC/Postfix/Exim/OpenSMTPD/Dovecot + 新目标）；与 Gmail/iCloud 的对齐留给 4-5 号门 |
| 伦理协议（自注册账号、限速、赏金规则） | MIMEminer §6.4 | Phase 4 模板已在案（DISCLOSURE_DRAFT.md） |

## 1. 现状与差距量化

**4 条可披露级**（dkimpy IndexError 崩溃、SnappyMail 外域 AR 绿徽章、rspamd 群组/domain-literal DMARC 静默、T5 mbox From 行歧义——后者 borderline）vs **MIMEminer 19 条**。差距构成：

1. **150 条候选未经确认工序**：20.7% 抽样机器复核 ≠ 披露标准。缺：聚类成族、最小重现子、RFC 条款判定（差分 vs 违规）、根因与后果陈述、上游查重。
2. **目标面窄**：13 个组件、全部自建开源栈；MIMEminer 是 16 检测器 × 7 客户端 = 128 组合。每加一个 parser/MTA 都在现有 39k 语料上直接产出新差分。
3. **语法深度浅**：单头生成 + depth-1 变异、无跨字段组合——组合空间（Chen 2020 的教训）未开。
4. **反馈未闭环**：w4 的幸存率统计没有喂回变异权重。

---

## 任务 A：候选确认工序（Phase 0，最高优先——用户已确认"都应详细确认"）

**Files:**
- Create: `E:\Gramfuzz\gramfuzz\cluster.py`、`E:\Gramfuzz\gramfuzz\reduce.py`
- Create: `received-lab/results/research/w5-<日期>a/confirm/`（families.json、reduced/、conformance.json、CONFIRMED-CANDIDATES.md）

### A1 家族聚类（150 → 机制家族）

- [ ] **Step A1.1 写失败测试** `E:\Gramfuzz\tests\test_cluster.py`：

```python
import sys
sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.cluster import family_key, cluster_rows


def test_family_key_groups_same_mechanism():
    rows = [
        {"case": "a", "entry": "obs-from", "op": "guided.space-colon",
         "views": {"python": (0, False, 0), "go": (0, True, 7), "node": (25, True, 7)},
         "relay": {"postfix": {"gen_preserved": False}, "exim": {"gen_preserved": True}},
         "verdicts": {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"}},
        {"case": "b", "entry": "obs-from", "op": "guided.space-colon",
         "views": {"python": (0, False, 0), "go": (0, True, 7), "node": (25, True, 7)},
         "relay": {"postfix": {"gen_preserved": False}, "exim": {"gen_preserved": True}},
         "verdicts": {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"}},
    ]
    fams = cluster_rows(rows)
    assert len(fams) == 1 and len(fams[0]["members"]) == 2
    assert fams[0]["representative"] == "a"


def test_family_key_distinguishes_verdict_shapes():
    a = {"entry": "from", "op": None, "views": {"python": (0, True, 7), "go": (0, True, 7), "node": (1, True, 7)}}
    b = {"entry": "from", "op": None, "views": a["views"]}
    a["verdicts"] = {"dkimpy": "fail", "rspamd": "fail", "perl": "pass", "go": "pass"}
    b["verdicts"] = {"dkimpy": "pass", "rspamd": "pass", "perl": "parse-error", "go": "pass"}
    assert family_key(a) != family_key(b)
```

- [ ] **Step A1.2 实现 cluster.py**：

```python
"""机制家族聚类：stage2 行 → 家族（入口×算子×views 形态×保留形态×判定形态）。

MIMEminer 的 19 条是聚类结果不是原始命中数——本模块做同样的折叠：
同族 = 同一机制在不同种子/字节上的重现。representative 取首例，
members 全留（证据链不丢）。
"""
from __future__ import annotations

import json
from pathlib import Path


def _shape(views: dict) -> tuple:
    return tuple(sorted((k, tuple(v) if isinstance(v, (list, tuple)) else v)
                        for k, v in (views or {}).items()))


def _preserved(relay: dict) -> tuple:
    return tuple(sorted((t, r.get("gen_preserved")) for t, r in (relay or {}).items()))


def _vshape(verdicts: dict) -> tuple:
    return tuple(sorted((k, v) for k, v in (verdicts or {}).items()))


def family_key(row: dict) -> tuple:
    return (row.get("entry"), row.get("op"), _shape(row.get("views")),
            _preserved(row.get("relay")), _vshape(row.get("verdicts")))


def cluster_rows(rows: list[dict]) -> list[dict]:
    fams: dict[tuple, dict] = {}
    for row in rows:
        key = family_key(row)
        fam = fams.setdefault(key, {"key": list(map(str, key[:2])), "representative": row["case"],
                                     "members": [], "n": 0})
        fam["members"].append(row["case"])
        fam["n"] += 1
    return sorted(fams.values(), key=lambda f: -f["n"])


def main(run_dir: str) -> None:
    stage2 = json.loads((Path(run_dir) / "stage2.json").read_text(encoding="utf-8"))
    rows = stage2["rows"] if isinstance(stage2, dict) else stage2
    fams = cluster_rows(rows)
    out = Path(run_dir) / "confirm"
    out.mkdir(exist_ok=True)
    (out / "families.json").write_text(
        json.dumps({"families": fams}, ensure_ascii=False, indent=1), encoding="utf-8")
    print("families:", len(fams), "| top:",
          [(f["key"], f["n"]) for f in fams[:8]])


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
```

- [ ] **Step A1.3 跑聚类**：`wsl bash -c "cd /mnt/e/Gramfuzz && python3 -m gramfuzz.cluster /mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz"`。产出预期 20–40 族（若 >60 说明 key 太细，把 views 里的 field_count 从 key 中降级为参考字段再聚一次，两版都存）。
- [ ] **Step A1.4 提交**（E:\Gramfuzz）：`git add gramfuzz/cluster.py tests/test_cluster.py && git commit -m "加入机制家族聚类：stage2 行折叠为可披露方法类"`。

### A2 最小重现子（ddmin）

- [ ] **Step A2.1 写失败测试** `E:\Gramfuzz\tests\test_reduce.py`（锚定已知最小形态：obs-colon From 的差分谓词在只剩 `From :x@y` + 模板时仍成立）：

```python
import sys
sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.reduce import ddmin_header


def _pred(raw: bytes) -> bool:
    # 谓词示例：python 认不出 From 而 go 认得出（stage-1 可重放的最小差分）
    import email, io
    try:
        m = email.message_from_bytes(raw)
        py_from = m.get("From") is not None
    except Exception:
        py_from = False
    return py_from is False and b"From" in raw


def test_ddmin_shrinks_to_essential_bytes():
    raw = (b"From : Bank Security <security@bank.test>\r\n"
           b"To: bob@lab.test\r\nSubject: s\r\n\r\nbody\r\n")
    out = ddmin_header(raw, _pred)
    assert _pred(out) and b"From :" in out
    assert len(out) < len(raw)
```

- [ ] **Step A2.2 实现 reduce.py**：

```python
"""最小重现子：对生成头块做字节级 ddmin，谓词由家族签名决定。

谓词接缝：每族的 representative 从 stage1/stage2 的机器判定导出一个
可重放谓词（P=三 parser 元组差分、T=gen_bytes 在存档中存活态翻转、
X=四验证器判定形态）。ddmin 只砍头区生成块，模板行（Subject/X-Case-ID
等）不参与——它们是定位与投递所需。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def ddmin_header(raw: bytes, pred, max_rounds: int = 24) -> bytes:
    zone_end = raw.find(b"\r\n\r\n")
    zone, body = raw[:zone_end], raw[zone_end:]
    lines = zone.split(b"\r\n")
    keep = [b"Subject:", b"X-Case-ID:", b"Message-ID:", b"To:", b"Date:",
            b"DKIM-Signature:"]           # 模板/定位行不参与缩减
    target = [i for i, l in enumerate(lines) if not l.startswith(tuple(keep))]
    # 行级缩减
    changed = True
    while changed and len(target) > 1:
        changed = False
        half = len(target) // 2
        for part in (target[:half], target[half:]):
            trial = [l for i, l in enumerate(lines) if i not in set(part)]
            if pred(b"\r\n".join(trial) + body):
                lines, target, changed = trial, [i for i, l in enumerate(trial)
                                                 if not l.startswith(tuple(keep))], True
                break
    # 行内字节缩减（对保留的生成行）
    for idx in range(len(lines)):
        line = lines[idx]
        if line.startswith(tuple(keep)):
            continue
        i = 0
        while i < len(line) and len(line) > 1:
            trial_line = line[:i] + line[i + 1:]
            backup = lines[idx]
            lines[idx] = trial_line
            if pred(b"\r\n".join(lines) + body):
                line = trial_line
            else:
                lines[idx] = backup
                line = backup
            i += 1
    return b"\r\n".join(lines) + body
```

（行级先半分、行内逐字节——标准 ddmin 两级；谓词每次调用是确定性机器判定，无网络。）

- [ ] **Step A2.3 每族最小化**：对每族 representative 导出谓词（P 族=stage-1 三元组差分重放；T 族=过对应中继后 `gen_bytes in stored` 与输入族形态一致；X 族=四验证器判定形态复现），跑 ddmin，产物 `confirm/reduced/<family-representative>.eml`。**锚定检查**：KB2 族的 reduction 必须仍呈 dkimpy parse-error / perl+go+rspamd pass——锚不中说明谓词导出有错，停下修。
- [ ] **Step A2.4 提交**（E:\Gramfuzz）：`git add gramfuzz/reduce.py tests/test_reduce.py && git commit -m "加入 ddmin 最小重现子：族代表压缩到本质字节"`。

### A3 规范符合性过滤（差分 → 违规）

- [ ] **Step A3.1 构建规范条目索引**（MailSecLab 侧工具脚本 + 产物）：

```python
# received-lab/research/lib/normative_index.py（构建脚本，产物进 w5 confirm/）
"""从六份 RFC 文本抽取 MUST/SHOULD/MUST NOT 句，编号入库供人工映射。"""
import re, json, sys
from pathlib import Path

RFC_DIR = Path("/mnt/e/Gramfuzz/rfc")
PAT = re.compile(r"(?im)^[^\n]{0,200}?\b(MUST NOT|SHALL NOT|MUST|SHALL|SHOULD NOT|SHOULD|REQUIRED)\b[^\n]{0,300}")

def build():
    index = []
    for f in sorted(RFC_DIR.glob("rfc*.txt")):
        rfc = f.stem.upper()
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            if PAT.search(line):
                index.append({"rfc": rfc, "line": i + 1, "text": line.strip()[:400]})
    out = Path(sys.argv[1]); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    print("normative statements:", len(index))

if __name__ == "__main__":
    build()
```

跑：`wsl bash -c "cd /mnt/e/MailSecLab/received-lab && python3 research/lib/normative_index.py results/research/w5-<日期>a/confirm/normative-index.json"`。预期 800–1500 条。

- [ ] **Step A3.2 逐族人工判定（LLM 辅助 + 人工确认，不可全自动）**：对每族 × 涉及组件，从 normative-index 找适用条款，判定三值：`violation`（违反明确 MUST/MUST NOT，可披露）/ `defensible`（各家都可辩护的组合缺陷）/ `unspecified`（规范未覆盖）。产物 `conformance.json`，schema：

```json
{"family": "obs-from/space-colon/dkimpy-parse-error", "component": "dkimpy",
 "behavior": "对注入的 obs-from 头抛 IndexError（非受控错误）",
 "rfc_clause": "RFC 5322 §3.6.2 (from 字段语法) / RFC 6376 §6.1",
 "quote": "…", "verdict": "violation", "confidence": "high",
 "minimal_reproducer": "confirm/reduced/gf-obs-from-….eml"}
```

重点核查方向（已知线索）：RFC 5321 §4.4（修改既有 trace 的限制——Postfix 改写 obs Received 是否越线）；RFC 8601 §5（边界删除 AR——OpenDMARC 只删本域）；RFC 6376 §3.5/§5.4（验证器对畸形字段实例的处理义务）；RFC 5321 §4.5.3（行长限制 vs 改写）；健壮性底线（崩溃类不依赖条款）。
- [ ] **Step A3.3 产出 CONFIRMED-CANDIDATES.md**：族表（族名、代表案例、成员数、最小子、根因、后果陈述、conformance 判定、建议系列编号接 TAXONOMY）。**exit 标准：violation 级 ≥ 10 条。**

### A4 上游查重与版本核查（只读网络，与文献检索同性质）

- [ ] 对每条 violation 级：上游 issue/commit 检索（dkimpy/rspamd/SnappyMail/OpenDMARC/Postfix/Exim/OpenSMTPD 各自 tracker）+ 当前最新版行为复测（新容器或本地装最新版，复现最小子）。产物并入 conformance.json：`upstream: {known: bool, fixed_in_latest: bool, ref: url}`。
- [ ] **提交**（MailSecLab research/received-trace）：`git add results/research/w5-*/ received-lab/research/lib/normative_index.py && git commit -m "w5 候选确认工序：家族聚类、最小重现子、规范符合性判定与上游查重"`。

---

## 任务 B：目标扩展（Phase 1——存量语料重放是最便宜的放大器）

### B0 存量重放（先做，零生成成本）

39k 语料仍在 w4 磁盘（未入 git 但在）。每个新 parser 目标接入后，直接对**现有语料**跑 stage-1 批量探针（parse_batch 语义），产出新 P 差分；每个新 MTA 目标接入后，对**现有 236 个 stage-2 案例**跑中继臂（capture 路由需重放手术，SURGERY.md 在案），产出新 T 差分。**不重新生成语料。**

### B1 eml_parser（法证角色——补上第四类消费角色）

- [ ] 安装：`wsl bash -c "python3 -m pip install --user eml_parser"`（setup 网络，与 RFC 下载同性质）。
- [ ] 写 `E:\Gramfuzz\parsers\parse_batch_emlparser.py`（host 直跑，不走 docker；输出同款 JSONL，`received_count`/`from_in_headers`/`field_count` 语义对齐）。
- [ ] funnel 的 `_run_*` 注册表加 `host` 类型探针（在 WSL 宿主直接 subprocess 跑，无容器）。
- [ ] **锚定**：对 w3 六锚语料跑一遍，v00/v02 与三家一致、v01/v03/v04/v07 与 python 或 go 分歧——记录它自己的判定形态（它可能站任何一边，这是新数据）。
- [ ] 重放：39k 语料 × eml_parser → 新 P 差分清单（预期数百条，聚类后并入 A1 族表）。

### B2 Ruby mail 库（MIMEminer 库优先原则）

- [ ] 容器：`wsl bash -c "docker run -d --name gf-ruby --network mailseclab-research-net -v /evidence:/evidence ruby:3.2-slim sleep infinity"` + `docker exec gf-ruby gem install mail --no-document`。
- [ ] 写 `parsers/parse_batch.rb`（同款 JSONL；`Mail.read_from_string` 的 from/received 计数）。
- [ ] funnel `_container_batch` 加 ruby 目标（tar 交付同 go/node）。
- [ ] 锚定 + 39k 重放。

### B3 Haraka（第四台 MTA，Node 生态）

- [ ] 容器：基于 parser-node 镜像 `docker commit` 一个 gf-haraka（`npm install Haraka`，配置接收→直投 msl-mailpit:1025 的简易插件——复刻 w3 手术的三台中继直投模式）。
- [ ] diffrun-targets.json 注册 `smtp:haraka`；**锚定**：v00-plain N=1 投递成功、v01-obs-colon 保留/计数行为记录（它可能呈第四种形态）。
- [ ] 对现有 236 案例跑中继臂（手术重放期间），新 T 差分并入族表。

### B4（可选，时间盒各半天）mailparse-rs（Rust）、neomutt（终端 MUA 渲染）

同样模式；neomutt 的渲染提取若 4 小时内不通则记仪器缺口放弃。

**B 组提交**：E:\Gramfuzz（探针 + funnel 注册）+ MailSecLab（重放产物进 w5 confirm/）。

---

## 任务 C：语法与组合加深 + w5 campaign（Phase 2）

### C1 新入口（entries.json 增补）

- [ ] 加：`msg-id`、`in-reply-to`、`references`、`orig-date`、`obs-orig-date`（5322，串钓鱼/线程欺骗轴）；`resinfo`（8601 的 AR 结果子句深水区）；`arc-ams-info` 深入（8617）。验证：每入口派生前缀测试过再入 entries。
### C2 组合变异（Chen 2020 教训的机制化）

- [ ] `phase_corpus` 升级：每样本以概率 p=0.3 从**两个不同入口**各生成一个头、拼在同一封信（如 DKIM-Signature + AR、From + Received）。mutate depth 默认 1，10% 样本 depth 2。
- [ ] 测试：组合样本的头两行分别命中两个入口的前缀。
### C3 反馈闭环（ReqsMiner/MIMEminer 经验）

- [ ] 新脚本 `gramfuzz/seed_weights.py`：从 w4 `stage1-summary.json` 的 by_op 幸存率导出 w5 初始 PriorityTable 权重（survivor_rate 归一化 × 全局先验），写 `weights-w5.json`；funnel 加 `--weights` 参数。
- [ ] 验证：space-colon/tab-colon 权重仍最高（w4 事实），case-name 因被去重吸收而降权——**并在 RECORD 里注明这是去重层阴性，不是实测阴性**。
### C4 w5 campaign

- [ ] 手术重放（SURGERY.md）→ 控制信 + KB2 锚 → `--phase corpus`（新入口 + 组合 + 新权重；规模 13+7 入口 × 2000 + 组合层 ≈ 45k）→ stage1（**含全部新 parser 目标**）→ stage2（cap 400）→ report。
- [ ] 走一遍任务 A 的确认工序（A1 聚类 → A2 最小化 → A3 符合性）。
- [ ] 栈回滚；RECORD.md；TAXONOMY 接续编号；AGENTS.md 更新。

**exit 标准：累计 violation 级 ≥ 19（对齐 MIMEminer 量级），或给出有依据的 shortfall 分析。**

---

## 任务 D：后果 oracle 与 Figure-1（Phase 3）

- [ ] 每族一条**后果陈述**：最终用户可见什么（徽章/身份/判决翻转/投递 vs 拒绝），证据指针到 webmail DOM/IMAP/验证器输出。模板三问：攻击者构造什么字节 → 哪个组件行为分歧 → 受害者最终看到什么。
- [ ] **Figure-1 组合案例**：一封信同时携带 obs 伪造 trace + 攻击者域有效 DKIM 签名 + 外域伪造 AR，过 OpenSMTPD→Postfix 链，四个观察点（OpenDMARC AR / rspamd 符号 / dkimpy / SnappyMail 徽章与 From）各截图——用 w4/w5 已有证据组装，只补缺失的截图。这是论文主图与「一封信四种现实」的叙事锚。

---

## 任务 E：披露批次（Phase 4，**gated——负责人开闸后才执行**）

前置：任务 A 的 violation 清单 + B/C 的增补。

- [ ] 按厂商分组打包（dkimpy / rspamd / SnappyMail / OpenDMARC / Postfix / Exim / OpenSMTPD / 新目标）：每包含最小子、版本矩阵、RFC 条款引用、影响陈述、复现步骤。
- [ ] DISCLOSURE_DRAFT.md 更新为批次草稿；伦理协议沿用 MIMEminer §6.4 模板。
- [ ] `gate.json` 的 `disclosure_sent` 保持 false 直到负责人批准发送。

---

## 验收与停止规则

- 确认工序不可跳步：未过 A2 最小化的族不进 A3；未过 A3 的条目不进披露包。
- 每族的最小子必须**重放机器判定**成功（谓词复验）才算 confirmed；KB2 与 w3 六锚是全程仪器锚。
- 新目标接入必须先过锚定（六锚语料 + v00/v01 控制信），锚不中不带病跑批量。
- violation 判定必须引用 RFC 原文行号；`defensible` 判定同样要写理由——三类都要可审计。
- 阴性照记（含「去重层阴性」与「实测阴性」的区分）。
- 实验不出公网；setup 期下载（pip/gem/npm/镜像）逐项在 RECORD 里留痕。
- TAXONOMY 编号只增不改；新族先 classify 归系列、root_cause 人工判定。

## 时间预算（单人，Phase 4 除外）

| 任务 | 预算 |
| --- | --- |
| A 确认工序（聚类/最小化/符合性/上游） | 3 天 |
| B 目标扩展（重放 + eml_parser + ruby + Haraka + 可选） | 3 天 |
| C 语法加深 + w5 campaign + 二次确认 | 4 天 |
| D 后果陈述 + Figure-1 | 1 天 |
| E 披露批次（gated） | 2–3 天 |

关键路径：A → B0（重放即刻并入 A 的族表）→ C → D；E 等 A+C 的 violation 清单与你的开闸。

## 与「19 条」的对账口径（诚实声明）

MIMEminer 的 19 = 真实商业产品上的确认绕过。我们的 violation 清单 = 开源基础设施组件上的规范违反 + 崩溃 + 欺骗原语（这些组件的部署量构成普适性论证，但不是「Gmail 上绕过」）。**数量口径对齐靠 A+B+C；「真实服务」口径对齐只有 4-5 号门（Phase E 之后）能补。**论文叙事两档都成立：开源全链条系统性 + 负责任披露的厂商确认。
