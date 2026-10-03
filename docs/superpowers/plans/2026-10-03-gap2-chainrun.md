# Gap 2 实验计划：变换链差分测试系统 chainrun（Transformation-Aware Differential Testing）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实施。步骤用 checkbox（`- [ ]`）跟踪。

**产出物：** 实验按任务推进，**run-id 用 `w6-<日期>a`（`w5-*` 已被 Gap 1 vuln-amplify 计划占用，避免产物目录冲突）**。

**Goal：** 把 w1–w4 已有的单跳/散点变换证据收束为系统化的链式差分测量系统：同一份种子字节 E₀ 经过**有序异构 MTA 序列**（可扩展 ARC / 邮件列表节点），在每一跳存档字节与判决向量，自动搜索「语义不可传递」的 flip 与非交换性；补上 ARC（RFC 8617 语义层零先例，GAP5 §八 P1#4）与被动语料流行率（GAP5 §八 P1#7）两个确认空白。对应 GAP2（变换链引擎/组合空间）+ GAP5 §三装配表的第二子系统。

**Architecture：** 三层，全部泛化既有代码、不另起炉灶：
① `chainseeds.py` 种子注册表——统一 diffrun 的 8 形态、sigprobe2 的 3 签名基线、repair 的 11 探针、w1 causal 的 From-above 突变体；
② `chainrun.py` 序列执行器——`remain.py` 的 ad-hoc 容器模式（`start_postfix/start_exim/start_osmtpd`）泛化：每序列起临时容器 `msl-cr-*` → 控制信 → 逐种子发送 → 双终点捕获（mailpit 字节臂 + auth 栈判决臂）→ 单跳前缀臂分离组合效应 → teardown；
③ `chainflip.py` 分析层——flip（终态判决 ∉ {norelay, 各单跳}）、非交换性（A∘B vs B∘A）、known.json 去重、minimize.py 最小化。
ARC 节点 = 栈内 rspamd arc 模块（seal/verify/adjust_dmarc）+ 源码构建 OpenARC 新容器（沿 `build_opendkim.sh` 离线构建先例）。事实只出自 `tracefacts.facts`，判决只出自 `verdicts`/`causal.verify_file`，证据走 `/evidence` + sha256。

**Tech Stack：** Python 3.11（msl-client / msl-verifiers 容器内）、docker compose 研究网（`mailseclab-research-net`）+ ad-hoc `docker run`、pytest（`research/tests/`）。

**工作目录：** WSL `/mnt/e/MailSecLab/received-lab`（实验与代码）；Windows `E:\MailSecLab`（计划文档与 AGENTS.md）。

---

## 与 Gap 1 验证（gap1-vuln-amplify，并行工作流）的冲突规避规则（负责人要求）

共享资源面与对应规则：
1. **run 目录**：Gap 1 占用 `results/research/w5-*`；本计划全部产物进 **`w6-*`**。
2. **栈手术**：Gap 1 的 B0 重放与 C4 campaign 需要 SURGERY（exim/opensmtpd→mailpit 直连、transport_maps）。本计划的栈操作（任务 0/3.6/5/7/8）执行前必须先核对 Gap 1 是否在跑（docker ps 活动容器 + `w5-*/confirm/` 与 Gramfuzz 仓库 mtime）；**Gap 1 campaign 运行期间：不清空 Mailpit、不重启 msl-dns/msl-auth-postfix/msl-rspamd、不动 exim/opensmtpd 容器配置、不改 rspamd/DNS/transport 配置**。
3. **共享文件只做加法**：`diffrun-targets.json`（Gap 1 B3 要注册 haraka，本计划完全不修改它——chainrun 用自己的序列注册表与 ad-hoc 容器）；`tracefacts.py`（MailTrace/Gramfuzz 契约文件，不改）；`run.py` 只追加 `chain` stage 注册。
4. **只读验证可并行**：`verify_file`（msl-verifiers 文件扫描）与 `rspamc` 文件扫描不发送邮件、不写 Mailpit、不改配置，可与 Gap 1 并行；sigprobe2 锚定回放属于此类。
5. **实施顺序**：代码任务（1/2/3/4 的实现与单测）完全不碰栈，立即开工；栈任务排在其后，按第 2 条规则择窗执行。ARC 手术（任务 5 的 rspamd/DNS 变更）是唯一必须独占窗口的操作。

---

## 0. 现实基线（执行任何任务前必读，不重做）

| 已有资产 | 证据位置 | 对本计划的意义 |
| --- | --- | --- |
| remain.py 两跳链雏形：6 路径 × 1 种子（From-above），容器编排完整 | w1 `remain/` | chainrun 的直接模板；缺 facts/判决向量/多种子/前缀臂 |
| diffrun 单跳矩阵：8 形态 × 3 MTA × 两臂 + parser 三列 | w3 `diffrun/` | 单跳臂即其前缀臂；VARIANTS/构建器直接复用 |
| sigprobe2 九格：3 签名基线 × 3 路径 × 4 验证器 | w3 `sigprobe2/` | 已知 flip 锚（s2 经 osmtpd→dkimpy parse-error vs 经 postfix→pass）；控制锚来源 |
| repair matrix：11 探针 × direct/osmtpd 完整；**exim 列 250 后捕获未通** | w2 `repair/` | 探针进种子表；exim 列由任务 3 单跳前缀臂补齐（任务 7） |
| w4 gramfuzz：150 条 lab_confirmed 候选 | w4 `gramfuzz/candidates.json` | 发现引擎已建成，本计划不重跑 campaign；候选可作后续种子扩展 |
| GAP5 §八装配清单：chainrun v0 = P0#2、ARC = P1#4、被动语料 = P1#7 | `results/research/GAP5-SURVEY-20261003.md` | 本计划即其执行文档；GAP3 的 oracle 事件分类学不在本计划内（verdicts 只留 `events=[]` 接口） |

环境坑（全部沿用既有记录）：`dockerctl` 拒绝非 `msl-` 容器名、legacy 栈与研究网互斥——链引擎用 ad-hoc `msl-cr-*` 容器绕开；双网容器取 10.88.* 地址；长 campaign 必须先起保活循环（`while true; do docker exec msl-client true; sleep 15; done`，w4 SURGERY 先例）；remain.py 的 ad-hoc exim（`received-lab-exim:latest`，配置 `/etc/exim/exim.conf`）与 w3 的 `exim` 容器（v3 镜像，`/etc/exim4/exim4.conf`）是两套布局，控制锚必须核对两者行为一致；OpenDKIM 必须是 libc 构建（w3 `opendkim-col/` 结论）；`causal.verify_all()` 已知损坏，用 `verify_file()`。

---

## 任务 0：栈基线与保活（P0，0.5 天；执行前按冲突规避规则核对 Gap 1 状态）

- [ ] 0.1 研究网起栈：`docker compose -p mailseclab-research -f research/docker-compose.yml up -d dns verifiers rspamd mailpit client` + auth 栈（auth-postfix/dovecot/opendkim/opendmarc）；确认 msl-opendkim 为 libc 构建（`probe_opendkim_dns.sh` 出查询）、msl-rspamd milter 仍在 auth-postfix 链尾（w2 STATE「未回滚」项）、legacy 栈全停。
- [ ] 0.2 起保活循环（后台，幂等——Gap 1 的保活循环与本计划共存无冲突），记录进程句柄到 run 目录 STATE。
- [ ] 0.3 跑一封 v00 控制信全链核对（**不清空 Mailpit**——按 case-id 定位即可，避免破坏 Gap 1 可能的在飞捕获）。

## 任务 1：verdicts.py 判决向量层（P0，TDD，0.5 天；纯代码+只读验证，不碰栈）

**Files：** Create `research/lib/verdicts.py`、`research/tests/test_verdicts.py`

- [ ] 1.1 失败测试先行。判决向量 schema（单个观察点上对一份字节收集）：
```python
{
  "bytes": tracefacts.facts(raw),                       # 字节事实（复用）
  "dkim": {"dkimpy": s, "perl": s, "go": s, "rspamd_file": s},   # causal.verify_file + rspamc
  "chain": {"smtp_code": "250", "delivered": True, "relay_chain": [...]},
  "ar": {"dkim": "...", "dmarc": "...", "header_from": "...", "header_d": "...", "rspamd_milter": [符号]},
  "envelope": {"from_first": "..."},                    # Dovecot IMAP ENVELOPE 首元素
  "events": [],   # GAP3 oracle 事件接口，本计划不实现分类学
}
```
- [ ] 1.2 实现：文件级四验证器复用 `causal.verify_file`；AR 解析与 IMAP fetch 从 `repair_matrix.py` 的 `unfold_ars`/fetch 逻辑**收编**进 verdicts.py（repair_matrix 保持原样不动）；rspamd milter 判决沿用日志 grep（`id: <<case_id>@lab.test>`）。`diff_verdicts(a, b)` → 逐字段 {persist, break, created}；erased/laundered 先作人工标注字段。
- [ ] 1.3 控制锚：回放 w3 `sigprobe2/matrix.json` 全 9 格（对存档 `.stored.eml` 重跑文件级验证器——只读操作，可与 Gap 1 并行），判决必须逐格复现；不符先修 verdicts 不改锚。
- [ ] 1.4 commit：`加入 verdicts 判决向量层，sigprobe2 九格锚定回放通过`

## 任务 2：chainseeds.py 种子注册表（P0，0.5 天；纯代码）

**Files：** Create `research/lib/chainseeds.py`、`research/tests/test_chainseeds.py`

- [ ] 2.1 注册表统一四源：8 形态（`diffrun.VARIANTS`，N=25）+ 3 签名基线（sigprobe2 s0/s1/s2，`sign_custom` + w1 cal 密钥 `results/research/w1-20261001a/keys/priv.pem`）+ repair 11 探针（`repair_matrix.build_probe`）+ From-above 突变体（w1 `causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml`）。每种子 `{name, build(case_id) -> bytes, known_single_hop: {...}, sink_admitted: bool}`。
- [ ] 2.2 全部种子过 `corpus_check`；有意 sink 的语料显式承认（v03/v04）。
- [ ] 2.3 commit：`加入 chainseeds 种子注册表（四源统一，corpus_check 全过）`

## 任务 3：chainrun.py 链引擎 + `chain` stage（P0 核心，1.5 天；代码先行，矩阵跑按冲突规则择窗）

**Files：** Create `research/lib/chainrun.py`；Modify `research/run.py`（STAGES/NEEDS/runners 加 `chain`，纯加法）；Test `research/tests/test_chainrun_sequences.py`

- [ ] 3.1 序列注册表 v0：**9 条有序对**（pf/ex/os 全排列 6 条 + 同 MTA 3 条 pf→pf/ex→ex/os→os）+ norelay 对照 + 单跳前缀臂（pf/ex/os 各一，终点 mailpit 与 auth 双终点）。三跳 6 条排列留 v1（任务 4 后按需）。
- [ ] 3.2 执行循环（remain.py 泛化）：每序列起 ad-hoc 容器（pf：`RELAYHOST=[ip]:port` env；ex：sed `/etc/exim/exim.conf` route_list；os：写 `/etc/smtpd.conf`）→ `wait_banner` → 控制信（v00 N=1 全链投递且 `relay_added`=跳数，不符停修仪器）→ 逐种子发送（case_id=`{seed}__{seq}__{arm}`，0.8s 间隔）→ teardown（`docker rm -f`）。
- [ ] 3.3 双终点两臂：**capture 臂**终点 `msl-mailpit:1025` rcpt `capture@lab.test`（字节 + facts + 文件四验证器）；**exec 臂**终点 `msl-auth-postfix:25` rcpt `bob@lab.test`（milter AR 三家判决 + IMAP ENVELOPE + Dovecot 原文）。fetch 沿 sigprobe2 修法：按 relay 标记 + X-Case-ID 字节匹配，无主题回退。
- [ ] 3.4 row schema：`{seed, sequence, arm, smtp_code, delivered, stored_path, input_sha256, facts, verdicts, known}`；`known.json` 去重；gate.json；挂进 run.py。
- [ ] 3.5 控制锚（仪器校验，全部应为已知结论）：s2 种子过 os→os 终态 obs 保留（dkimpy parse-error）vs pf→os 终态 strict（pass）；v01-obs N=55 计数组合（计数集合并集决定阈值跳位置）；ad-hoc exim 与 w3 `exim` 容器在 v01 capture 臂行为一致（obs 保留 + 计数）——不一致即停，查镜像差异。
- [ ] 3.6 跑全矩阵（9 序列 × ~24 种子 × 3 臂 ≈ 650 发送，保活！，Gap 1 空闲窗口执行），RECORD.md 固化判决表。commit：`加入 chainrun 链引擎与 chain stage，九序列全矩阵首跑`

## 任务 4：chainflip.py flip 与非交换性搜索（P0，1 天；代码先行）

**Files：** Create `research/lib/chainflip.py`

- [ ] 4.1 flip 定义与实现：终态判决向量 ∉ {norelay 向量, 任一单跳前缀向量}（组合专属翻转）；path-dependence：verdicts(A→B) ≠ verdicts(B→A) 同种子；字节级非交换：facts(A→B) vs facts(B→A) 逐字段。
- [ ] 4.2 `candidates.json`：每 flip 附四件套证据链（输入/各跳存档/SMTP 转录/全向量）+ `minimize.py` 最小化（仅 sig 不变类适用）。
- [ ] 4.3 复核：20% 抽样重跑（w4 惯例）；已知锚（sigprobe2 s2 族）标 `known=true` 不计新发现。
- [ ] 4.4 commit：`chainflip 首轮：组合专属 flip 与非交换性候选目录`

## 任务 5：ARC 节点（P1，新容器授权；rspamd ≤2 天 + OpenARC ≤5 天；**需独占栈窗口，与 Gap 1 协调**）

**Files：** Create `research/auth/openarc/Dockerfile`、`research/lib/build_openarc.sh`、`research/lib/arc_probe.py`；Modify rspamd 配置（运行时 override，备份入 run 目录）

- [ ] 5.1 拓扑（双 rspamd 实例设计，避免单实例角色冲突）：转发域 `fwd.lab.test` = ad-hoc postfix `msl-cr-fwd`（`smtpd_milters=inet:msl-rspamd-arc:11332`，**新容器** msl-rspamd-arc 从现有镜像起、配 seal）；接收域 = 既有 `msl-auth-postfix` + msl-rspamd（配 arc verify + `adjust_dmarc`）。DNS：`arc1._domainkey.fwd.lab.test` 密钥进 `extra-dns.conf` + msl-dns 重启（e2e.py 先例）；authserv-id 信任表指向 fwd。
- [ ] 5.2 rspamd arc spike（≤2 天上限）：三个 oracle 事件各一控制例——seal 产生（ARC-Seal/AMS/AAR 齐全）、verify 判定（ARC_ALLOW/REJECT/INVALID 符号）、adjust_dmarc 生效（信任转发器 seal 后 DMARC 判决变化）。
- [ ] 5.3 OpenARC 源码构建（≤5 天上限）：Dockerfile 沿 `auth/opendkim-libc` 模式（build-essential + autoreconf；源码 tarball host 侧下载 COPY 或经 host proxy curl；**libc resolver**——libunbound 不出容器是 w3 已知教训）。作为 milter 挂第二接收 postfix `msl-cr-rcv-oarc`。失败 → 仪器缺口记录（parsedmarc 先例格式），ARC 差分降为 rspamd 单实现，不阻塞主线。
- [ ] 5.4 ARC 语义矩阵：**(A1) 判决保持**——任务 4 的 flip 种子过 seal 链，接收端 ARC 验证/adjust_dmarc 是否恢复或进一步改变判决；**(A2) laundered**——无钥伪造 seal（应 fail，阴性锚）、诚实转发器对未验证信 seal（adjust_dmarc 翻转 DMARC reject？受控版 Zoho 场景）、攻击者自 seal 非信任域（应不缓解）；**(A3) 歧义 × ARC 头族**——多 ARC-Seal 实例/`i=` 非连续/`i=0`/obs-colon in ARC-Authentication-Results/重复 AMS 的实例选择（顶部 vs 底部）跨两实现；`c=relaxed`（省 body 规范化，RFC 6376 §3.5 合法）形态只记语义行为不追崩溃（CVE-2026-100895 内存层与本计划正交，只声明不复现）；**(A4) 互操作**——rspamd seal→OpenARC verify 与反向。
- [ ] 5.5 RECORD + commit：`ARC 节点接入：rspamd arc + OpenARC 双实现的语义矩阵`

## 任务 6：被动语料流行率（P1，host 侧，2–3 天；不碰栈，与 Gap 1 无冲突）

- [ ] 6.1 host 侧下载（Windows 有网，实验室无网不受影响）：lore.kernel.org / W3C / IETF 公共邮件档案（现代全头 raw mbox）+ SpamAssassin public corpus / Nazario / CEAS 2010（历史对照）。存 `received-lab/corpus/<name>/`（gitignore，同 gramfuzz corpus 惯例；只提交 sha256 清单）。
- [ ] 6.2 `research/lib/corpus_scan.py`（可复用模块，GAP4 §五.7 trace 特化共用）：tracefacts + 扩展检查（重复 From / 外域 AR / obs 形态 / 8bit 名 / domain-literal / by≠from 不一致）。
- [ ] 6.3 产出 `prevalence.json` + `PREVALENCE.md`：触发字节的在野出现率，映射到 w1–w4 已确认的差分结论。
- [ ] 6.4 commit：`被动语料流行率首轮：公共档案+经典语料扫描`

## 任务 7：repair exim 列补齐（P1，并入任务 3 执行，0.2 天）

- [ ] 7.1 repair 11 探针作为种子过 exim 单跳前缀臂（mailpit 直连终点）→ 填 SYNTHESIS L2 的 exim persist/break/created 列；解除 GAP2 调研的账本预埋（「exim 直连捕获跑通前不引用」）。

## 任务 8：mlmmj 列表算子（P2 限时 2 天，超时 parked；需栈窗口）

- [ ] 8.1 新容器 `msl-mlmmj`（bookworm + mlmmj 1.3.0-4，apt 走 host proxy 先例）；`msl-auth-postfix` transport_maps 加 `list@lab.test → pipe mlmmj-recieve`（transport 手术先例，STATE 记回滚）。
- [ ] 8.2 算子观测：Subject 前缀 / footer 正文追加（DKIM `l=` 交互轴）/ Reply-To munging / List-* 注入后的 facts+verdicts 变化；mlmmj 无环头对照 GAP4 T3。
- [ ] 8.3 commit 或 parked 记录。

## 任务 9：Return-Path / refold 小算子（P2，0.5 天；种子构造纯代码，跑臂需栈窗口）

- [ ] 9.1 Return-Path：各观察点字节对比定位添加者/时机；预置伪造 Return-Path 的覆盖/共存行为；与 ENVELOPE 探针联动。
- [ ] 9.2 refold：998+ 长行与非规范折叠种子过链，观测 MTA 是否重折叠（预期阴性为主，照记）。

## 任务 10：收尾与账本（P1，1 天）

- [ ] 10.1 run `RECORD.md` 全量固化；SYNTHESIS 增补链层（L2 组合关系 / L3 flip 目录 / erased-laundered 标注）；PAPER_SKELETON 问题句扩展为「变换链是否保持安全语义」并更新 What this run supports/does not support。
- [ ] 10.2 AGENTS.md：「已可引用的结果」增补链引擎与 ARC 结论行；「后续开发」加本计划指针；「不要写成定论」按新阴性/预埋更新。
- [ ] 10.3 栈回滚：ad-hoc `msl-cr-*` 容器全清、mlmmj/ARC 手术按 STATE 回滚表恢复、保活停、`docker compose ps` 核对；gate.json `disclosure_sent` 保持 false（新披露候选只记录进 DISCLOSURE_DRAFT 候选区，不发送）。

---

## 不做清单（本计划的负空间）

- 不重跑 w4/w5 campaign；不再扫更大 N（F3 已闭合；N=55 只作计数组合控制锚）。
- 不做 Thunderbird / 发送侧矩阵 / Sieve / ruf 路径（GAP5 P1#5/#6 项，另计划）。
- 不做 ASan 崩溃 oracle 与 CVE-2026-100895 内存层复现（GAP5 P2#10 项）。
- 不实现 GAP3 的 oracle 事件分类学与 SIS（verdicts 只留 `events=[]` 接口）。
- 不占用 `w5-*` run 目录、不修改 `diffrun-targets.json`、不修改 `tracefacts.py`（Gap 1 / MailTrace 共享契约）。
- 不出公网发信、不联系厂商、不公开发布；语料只下载不投递。

## 验收与停止规则

- 每个矩阵格四件套证据链：输入 `.eml` + sha256、SMTP 转录、存档 raw（或明确 miss 原因）、判决向量全量；定位邮件用 `X-Case-ID`，头区可能被终结时在整封 raw 里搜。
- 事实只出自 `tracefacts.facts`，判决只出自 `verdicts`/`verify_file`；任何脚本里再出现手写 Received 计数或手写 DKIM 判定即为缺陷。
- 控制锚不符 → 停下修仪器，不带着坏仪器跑矩阵；工具失败不记作阴性；known.json 去重；阴性照记。
- 与既有结论矛盾（如 ad-hoc exim 与 w3 exim 行为分歧）：先疑仪器（镜像/版本/配置路径），复现两次后才改写结论，并在 AGENTS.md「不要写成定论」留修正痕迹。
- ARC/OpenARC/mlmmj 各有硬上限，超时 parked（STATE.md parked 条目格式），不阻塞主线。
- Gap 1 campaign 在跑时，本计划的栈任务一律让行（见协调规则）；让行不视为 parked。
- 每任务完成 = 代码/证据 + RECORD/AGENTS.md 同步 + commit，三者缺一不算完成。

## 时间预算（单人）

| 任务 | 预算 |
| --- | --- |
| 0 栈基线 | 0.5 天 |
| 1 verdicts | 0.5 天 |
| 2 chainseeds | 0.5 天 |
| 3 chainrun + 首跑 | 1.5 天 |
| 4 chainflip | 1 天 |
| 5 ARC（rspamd 2 + OpenARC ≤5） | ≤7 天 |
| 6 被动语料 | 2–3 天 |
| 7 repair exim 列 | 0.2 天（并入 3） |
| 8–9 P2（mlmmj/Return-Path） | 各限时 |
| 10 收尾账本 | 1 天 |

关键路径 0→1→2→3→4→10；任务 5 可与 3–4 部分并行（verdicts 就绪即可开工，但栈手术需独占窗口）；任务 6 独立可随时插空。P0+P1 合计约 2.5–3 周，全量含 P2 约 4–5 周。对齐 GAP5 场次判断：USENIX Sec 2027 C2（2027-01-26 论文截止）为主目标，本计划是 16 周窗口里「组合空间」子系统的执行文档。
