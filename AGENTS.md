# MailSecLab

隔离的本地邮件安全实验室。当前研究不是「Received 能不能无限变长」，而是：RFC 5322 对 Trace 数量不设上限，真实 MTA、解析器和 DKIM 验证器各自用不同规则识别同一段字节，这种不一致会不会改变投递或认证结果。

负责人：朝阳（git 作者 YUN GU，GitHub DrNbnonono）。实验在 2026-08 至 2026-09 完成主测量，尚未写作或投稿。不要把实验室阴性写成「某漏洞已不存在」，也不要向公网发信。

## 证据优先级

文字结论互相冲突时，按这个顺序采信：

1. 原始 `.eml` 与节点日志
2. CSV 等结构化结果
3. `received-lab/results/*/RECORD.md`
4. `notes/` 里的综述

`notes/` 在 `.gitignore` 中，只存在于本机：`项目内容整理.md`、`项目内容调研.md`、`项目试验记录.md`。提交进仓库的事实以 `received-lab/results/` 为准。

环境快照：`received-lab/freeze/PF37-manifest.md`、`received-lab/results/phase3/env.json`。

## 环境与操作

Windows + WSL2 + Docker Desktop。命令在 WSL 里执行，工作目录是 `/mnt/e/MailSecLab/received-lab`。

默认拓扑：`mail-client → postfix1 → postfix2 → postfix3 → Mailpit`。Mailpit Web UI 只绑 `127.0.0.1:8025`。不出公网。

| 组件 | 本实验室版本 |
| --- | --- |
| Postfix | 3.7.11（PF37）、3.11.6（PF11） |
| Exim | 4.96 |
| OpenSMTPD | 6.8.0p2 |
| Mailpit | v1.31.0 |
| rspamd | 3.4 |
| dkimpy | 1.1.8 |
| 其余验证器 | perl Mail::DKIM、go-msgauth v0.6.8 |

Compose profile：默认三跳 Postfix；`mta3b` 为 Exim / OpenSMTPD；`pf11` 为 Postfix 3.11；`parsers` 为 Node / Go；`frspamd` 为 rspamd。

第二套栈：研究网 `mailseclab-research-net`（msl-auth-postfix + OpenDKIM/OpenDMARC/rspamd milter + Dovecot + Roundcube/SnappyMail + msl-dns + msl-mailpit + Exim v3/OpenSMTPD），用于 w1/w2 认证链实验。当前栈状态与回滚表见 `received-lab/results/research/w2-20261002a/STATE.md`。

语法引擎：独立仓库 `E:\Gramfuzz`（远端分支 `tool/gramfuzz`，与本仓库分离）——ABNF 语法差分 fuzz（abnf/gramgen/grammut/funnel 四层，RFC 5321/5322+obs/8601/6376/8617/6532/2045 驱动，13 个顶层头入口）。经 `gramfuzz.lab` 桥引用本仓库的 diffrun/tracefacts/evidence 与 diffrun-targets.json（单一事实来源，不复制）；运行产物落 `results/research/<run-id>/gramfuzz/`（/evidence 挂载映射）。实施计划见 `docs/superpowers/plans/2026-10-03-gramfuzz.md`，调研依据见 `results/research/GAP1-SURVEY-20261003.md`。

E、I、J3 会改 `relayhost`。换实验前执行 `docker compose restart postfix1 postfix2 postfix3`，并核对三条路由都恢复。Docker Desktop 的 resource-saver 会停掉 WSL 虚拟机，长实验需要保活。

新语料必须做头区结构自检。折叠生成器若在已有 CRLF 上再 `"\r\n".join()`，会造出双 CRLF，头区提前结束。`--style folded` 还可能在同一 Received 里放两个日期，不能当成严格合规的长 Received。

bookworm 的 `opendkim-testmsg` 对一切输入报语法错误，不能当 DKIM 验证器。

## 已可引用的结果

协议：RFC 5322 的 trace 条数 unlimited；RFC 5321 要求能停环，计数阈值只是 SHOULD，且通常不少于 100。实现阈值是配置，不是协议常数。

数量边界（默认配置）：

- 三跳 Postfix，`hopcount_limit=50`：预置 N≤46 投递（最终 Received=N+4）；N=47 由 postfix3 拒绝并退信；N=48 由 postfix2 拒绝；N≥49 由 postfix1 在 DATA 回 `554 5.4.0 too many hops`。
- 单跳：Postfix N=48 投递、N=49 回 554；Exim 从 N=30 起接受后退信（`received_headers_max` 30）；OpenSMTPD N=99 投递、N=100 回 `500 5.4.6`；Mailpit 到 N=120 仍收。
- F3：把 Postfix 调到 100 或把 Exim 调到 60，边界跟着移动。
- `hopcount_limit=8` 的真实环在第 8 跳终止。空信 DSN 放大见 F4：152 B → 4,853 B（31.9×）。不要和 E5 的 205 B → 约 23.8× 合成一个数。

识别差异：

- `X-Received`、`Received-SPF` 不计入 hopcount。大小写变体 `rEcEiVeD` / `RECEIVED` 计入。
- `Received :`（冒号前空白，RFC 5322 obs-received）×100：Postfix 规范化后计数并 554；Exim 保留空白但仍计数，接受后退信；OpenSMTPD 保留这 100 条空白变体且不计入环路阈值。以 `received-lab/results/e-series/e3raw/E3-OSMTPD-received_sp.eml` 为准。严格解析、Python、Go 计 2 条，Node 计 102 条。
- `Receíved`（U+00ED）在 Postfix 路径上会结束头区，后续字段降成正文。Phase 3 语料 V007：python-email 把 From 放进正文，Go 和 Node 仍当头。
- Phase 2 FC150：约 150KB 的折叠 Received 被截到 101,701 B 后仍投递。
- H：没有诚实中继时，文件扫描里 1 条伪造 `192.0.2.10` 就能成为 rspamd 的 source。经过 postfix1 后，source 回到真实会话地址（H3 为 172.22.0.5）。H 系列关闭了依赖 DNS 的 rspamd 模块，分数变化不能解释成 SPF 被绕过。
- I1：本环境已打补丁的 Postfix 3.7.11 与 Exim 4.96 上，SMTP 走私为阴性（first/smug=1/0）。这与 Debian bookworm Postfix ≥3.7.9 的修复线一致，不能外推到未修补版本。

DKIM（密钥 RSA-2048，`d=lab.test`，`s=j1`，relaxed/relaxed）：

- J1：`h=` 覆盖约 150KB 的 `X-Gen`。中继前 154,562 B 为 pass，三跳后 103,283 B 为 FAIL，SMTP 仍 250。
- J2：`l=33` 再追加 101 B，dkimpy 前后都 pass。这是 RFC 6376 §3.7 的前缀语义，不是新的协议漏洞。`l=` 只管正文长度，不管头区。
- J3：签名后插入 `Receíved`，dkimpy 拒解析；过 Postfix 后签名沉入正文。
- K 的最终矩阵以 `received-lab/results/k-series/RECORD.md` 和 `k1_matrix.csv` 为准。KB1 四家都接受。KB2（签名后注入异常头）：dkimpy 拒解析，perl 与 go-msgauth pass，rspamd `R_DKIM_ALLOW`（分数 4.3，动作 greylist）。KB3（重复 From）：dkimpy FAIL，rspamd `R_DKIM_REJECT`，perl 与 go pass。`l=` 追加时 go-msgauth 报 insecure body length tag，另外三家接受。DKIM 实例选择已有 causal 证据（perl/go/OpenDKIM 自底向上、dkimpy/rspamd 双实例 fail、oversign 全 fail）。

认证链与研究网（w1/w2，`received-lab/results/research/`）：

- OpenSMTPD 同构双中继环：普通与 `Received :` 种子都在约 100 条普通 Received 处被 5.4.6 停住（w1 `osmtpd-loop/`）。
- DKIM 实例选择：perl/go 自底向上，dkimpy/rspamd 双 From 即 fail，oversign 四家全 fail；From-above 突变体三跳 Postfix 后 perl/go 仍 pass 且投递，Roundcube 显示 Author、SnappyMail 显示 Attacker（w1 `causal/`、`report/PAPER_SKELETON.md`）。
- rspamd `get_from_ip()` 取顶部 Received 的 from-clause：自洽伪造链文件扫描时 source=伪造值，过诚实中继后恢复真实地址（w1 `i2/`）。
- OpenDMARC 1.4.2 不做 U-label→A-label 转换（RFC 9989 §5.3.1），原始 UTF-8 qname 永远 NXDOMAIN；同一信 OpenDMARC `dmarc=none` vs rspamd `DMARC_POLICY_REJECT`；执行翻转 550 vs 250；rua 聚合永远看不到 U-label 事件（w2 A 线）。核心已由 CVE-2026-100891 覆盖，增量见 w2 `UPSTREAM.md`。
- 显示层把 A-label/NFC/NFD 三种 From 全部渲染为受害者 Unicode 品牌（w2 `display/`，5 张截图）。
- repair matrix：七个单跳差分性质过 Exim/OpenSMTPD 中继后的 persist/break/created（w2 `repair/`）。
- recfuzz2：`Received` 八种语法形态 × 三 MTA，OpenSMTPD 对 `Received :`×55 保留 55 条、只计 2 条普通行仍 250 投递（w2 `recfuzz2/matrix.json`）。
- diffrun（w3）：八形态 × 三 MTA × 两臂统一矩阵 + parser 三列（python/go/node）。Exim 捕获臂确认 obs 字节保留但计数；更正 recfuzz2 的「exim 计 nocolon」误读（实为投递不计数）。python email 对 obs/nocolon/8bit/tab 在首条不合规行终结头区，Go net/mail 八形态头区全存活，Node mailparser 把 obs 与 tab 都计入（w3 `diffrun/RECORD.md`）。
- sigprobe2（w3）：对 obs 形态签名的 DKIM 12 格全灭（无验证器/路径验过）；签名后注入 obs——OpenSMTPD 保留它使 dkimpy 拒解析带进邮箱，Postfix 规范化它使 dkimpy 反而 pass（修复消除验证分裂的最干净实例）（w3 `sigprobe2/RECORD.md`）。
- parsedmarc（w3）：DMARC 聚合报告消费端零来源认证——冒名 Google 的伪造报告（捏造 IP×5000 条）被完整摄入；结构残缺拒收。消费侧照单全收 + 发送侧 U-label 空洞 = 监控完整性缺口两半（w3 `parsedmarc-probe/`）。
- gramfuzz 首轮 campaign（w4）：ABNF 语法驱动 39,000 样本（13 入口 × fresh/mutated）→ 三 parser 差分漏斗幸存 10,119 → 去重 236 入三臂 → **150 条实验室确认候选**（T=138/X=39/D=12，四件套证据链完整，20.7% 分层抽样复核 0 flag）。新原语四条：mbox `From ` 行歧义（一字节类别翻转 Postfix 整个处理路径，T5）、第二 DKIM-Signature 实例注入的四验证器新分裂（X7/X8）、Exim 尾部空白折行丢弃（T6）、Dovecot ENVELOPE 占位语义（D5）——分类学见 `results/research/TAXONOMY.md`（24 条）。工具在独立仓库 `E:\Gramfuzz`；corpus 不入库，CORPUS_SEED=20261003 可重放（w4 `gramfuzz/candidates.json`、`RECORD.md`）。

## 不要写成定论

- F1「rspamd 丢掉 9MB 头」已撤回。原因是语料双 CRLF，头区早就结束。纠正后的真折叠头块上，rspamd 约 56 ms、分数 3.4、无动作。
- G 系列「OpenSMTPD 改写 `Received :` 但不计数」与 E3 原始邮件冲突。OpenSMTPD 是保留空白、不计数。
- G4 已由 w1 重跑关闭；只引用 w1 的 8,000,545 B 折行语料数字。
- I2 已由 w1 重做关闭；注意结论是双向的：自洽伪造链在无诚实中继时确实能主导 rspamd 文件扫描的 source，诚实中继之后恢复真实地址。
- 没有测过 Gmail、Exchange 等托管服务，也没有真实互联网测量。
- OpenSMTPD 同构环已做（w1）：空白变体不让真实环路越过 5.4.6。不要再写「未测环路」。
- U-label 机制核心已被 CVE-2026-100891（2026-09-28）覆盖，本实验室为独立复现；增量（rua 报告空洞、NFD 阴性、显示层、服务端消费面）见 w2 UPSTREAM.md。不要写成全新漏洞。
- w1/w2 的结论来自研究网栈（msl-auth-postfix/OpenDKIM/OpenDMARC/rspamd milter/Dovecot/Roundcube/SnappyMail/msl-dns），与默认三跳 Postfix 栈是两套环境，结论不要互相搬用。
- 未向 Postfix、Exim、OpenSMTPD、rspamd、dkimpy 披露。K 的验证器差分和 J3 淹没不要直接写成漏洞。

## 文献与教程

阅读顺序和与实验的对应关系见 `references/README.md`。本地 PDF 包括 Sanchez 2010（`CEAS-2010-sdp.pdf`）、Van Staden 2010、Chen 2020、Shen 2021、Liu 2023、Luo 2025、Wang 2025、Andarzian 2025，以及 RFC 5321 / 5322。近五年顶会还没有做系统检索，不要写「无人研究过」。

`tutorials/` 是这 8 篇论文的本地讲解页，交互脚本在 `tutorials/assets/play.js`。页面在 `tutorials/<slug>/`。用仓库根目录的普通静态服务时，地址是 `/tutorials/<slug>/`；`python tutorials/dev_server.py` 会把 `/<slug>/` 也指到同一目录。演示里的 IP 和哈希是教学示例，论文数字以页面正文和 PDF 为准。

## 后续开发

1. ~~重跑 G4~~ 已关闭（w1）：`results/research/w1-20261001a/g4/`——78 字节折行语料，N1/N50/N100 全投递，N100 存档 8,000,545 B、100 条 X-Received 无缺口。旧 9,096,191 B 数字作废，不要再引用。
2. ~~重做 I2~~ 已关闭（w1）：`results/research/w1-20261001a/i2/`——自洽伪造链在文件扫描时确实把 rspamd source 指到伪造 from-clause；过诚实中继后回到真实会话地址；不自洽链被 join 检出（by-host ≠ from-host）。
3. ~~OpenSMTPD 同构环~~ 已关闭（w1）：`results/research/w1-20261001a/osmtpd-loop/`——普通与空白种子都在约 100 条普通 Received 处被 5.4.6 停住。空白变体保留原样、不计历史行，但中继自己新增的普通行仍计数，不破坏环路终止。
4. ~~DKIM 重复字段选择~~ 已关闭（w1 causal + w2 exec）：perl/go 自底向上取实例；dkimpy/rspamd 对第二实例 From 直接 fail；h= 重复列出（oversign）四家全 fail。实例绑定全景：DKIM/perl/go/OpenDKIM=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部、SnappyMail=顶部（OpenDKIM 列=w3 `opendkim-col/`，上插 pass/下插 fail）。
5. ~~Exim 4.92 阳性对照~~ 已关闭（w1 `exim492/`）：CRLF 载荷 554 同步错误、LF 载荷注入留在单个正文，与 I1 修补版阴性一致。

当前真正开放的项目：

1. ~~recfuzz2 的 Exim 捕获臂~~ 已关闭（w3 diffrun）：Exim 直投 msl-mailpit 的捕获路径确认 obs 字节保留但计入 hopcount——「保留」与「计数」是独立维度。
2. ~~parser 三家~~ 已关闭（w3 diffrun parse 列）。
3. ~~DKIM 验证器 × obs-colon 交叉~~ 已关闭（w3 sigprobe2）。
4. ~~OpenDKIM 公钥检索~~ 已关闭（w3 `opendkim-col/`）：根因=libunbound 构建的解析路径不出容器（unbound:probe A/B 对照：同信 key-not-found+零查询 vs libc 版 pass+有查询）；实例绑定列已补——OpenDKIM=底部选择。
5. ~~parsedmarc 报告消费端~~ 已关闭（w3 `parsedmarc-probe/`）：parsedmarc 11.0.3 做结构校验、**不做来源认证**——冒名 reporter + 捏造行数据的伪造聚合报告被完整摄入（`verdict.json`: forged=true, origin_verification_seen=false）。与 w2 rua 发送侧空洞合拢为监控生态完整性缺口的两半。
6. ~~gramfuzz 全量 campaign~~ 已关闭（w4）：39,000 样本 → 150 条 lab_confirmed 候选（`w4-20261003a/gramfuzz/candidates.json`），栈已回滚核对。
7. 真实服务验证与披露（调研建议 4/5 号）：**门是 candidates.json 非空且证据链完整，负责人决策后另行计划**。未获授权不联系厂商、不公开发布、不出公网。
8. Gap 2 变换链差分（chainrun）：计划见 `docs/superpowers/plans/2026-10-03-gap2-chainrun.md`——verdicts 判决向量层、有序异构 MTA 序列链引擎（双终点两臂 + 单跳前缀臂）、flip/非交换性搜索、ARC 节点（rspamd arc + OpenARC）、被动语料流行率。run-id 用 `w6-*`（`w5-*` 留给 Gap 1 vuln-amplify）；与 Gap 1 并行执行的冲突规避规则见计划首部。

改实验脚本时，比较的是同一字节流在不同组件上的解释。定位邮件用 `X-Case-ID`；头区可能被终结时，改为在整封 raw 里搜索。
