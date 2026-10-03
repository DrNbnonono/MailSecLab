# 邮件顶层头攻击分类学（P/T/X/D × 根因）

组织规则：**系列 = 首个分歧动词在五阶段生命周期（生成→解析→变换→信任→展示）中的位置**；跨阶段的影响记为链（如 T→X）。根因四选一：tolerance（语法容错位置）/ repair（修复策略）/ trust-boundary（信任边界假设）/ normalization（归一化与实例选择策略）。

条目来源：#P1–#D4 由 w1–w3 手工实验确立（gramfuzz 计划任务 8 草表）；#T5–#D5 由 w4 首轮语法 campaign 新增（39,000 样本，见 `w4-20261003a/gramfuzz/candidates.json` 与 `RECORD.md`）。新发现按同一规则接续编号。阴性地图见 `SYNTHESIS.md`，不在本表重复。

## P —— 识别差分（同字节，识别出的字段集合/边界/计数不同）

| ID | 原语 | 根因 | 证据 |
| --- | --- | --- | --- |
| P1 | obs-colon 计数：Postfix 计 / Exim 计 / OpenSMTPD 不计（字节保留维度另见 T1） | tolerance | w3 `diffrun/`；E3 |
| P2 | 盲区族：nocolon/8bit/cfws/comment 四形态，三台环路计数器全盲 | tolerance | w3 `diffrun/` |
| P3 | 8-bit 字段名终结头区，后续字段沉正文 | tolerance | w2 `eai/` A-3；V007 |
| P4 | parser 三命运：python 头区死亡 / go 忽略 / node 计入（w4 一般化到全部 13 入口族） | tolerance | w3 `diffrun/` parse 列；w4 `stage1.json` |
| P5 | 末位 tag 优先：DKIM d= / 密钥 p= / DMARC p= 三层独立出现 | normalization | w2 `keyprobe/`、`dmarcfuzz/`、`align2/` |

## T —— 变换差分（中继对字节的改写不同：规范化/保留/折叠/沉没/新增）

| ID | 原语 | 根因 | 证据 |
| --- | --- | --- | --- |
| T1 | obs 行字节：Postfix 改写 / Exim 保留 / OpenSMTPD 保留（保留与计数为独立维度）。w4 扩展：obs 冒号规范化不止 Received——`From\t\t\t:` 等身份头同样被 Postfix 改写为 `From:` | repair | w3 `diffrun/` 捕获臂；w4 `relay/` |
| T2 | 修复决定判决：同一注入信，osmtpd 保留使 dkimpy parse-error 入箱，postfix 规范化使其全 pass | repair | w3 `sigprobe2/` s2 |
| T3 | 单跳性质过异构中继 persist/break/created（七个性质 × Exim/OpenSMTPD） | repair | w2 `repair/` |
| T4 | obs 形态不可签：12/12 格无验证器/路径验过（防御侧强结果） | repair | w3 `sigprobe2/` s1 |
| T5 | **mbox `From ` 行歧义**：首行 `From`+空格 → Postfix 抬升为 `X-Mailbox-Line:` 并在该行终结头区，DKIM-Signature 与全部身份头沉入正文；空格 vs 仅 tab 一字节类别翻转整个处理路径（`From \t:"` 沉没 vs `From\t\t\t:` 被规范化）。判定链：文件级 dkimpy=tool-error / perl+go+rspamd=pass → 过 postfix 后 perl/go/rspamd=none（signature_count:0） | repair | w4 `sign/`（gf-obs-from-fresh-000{0,2}-sign，7 例） |
| T6 | **Exim 尾部空白折行丢弃**：头部前段逐字节保留、尾部纯 WSP 折行被丢（postfix/osmtpd 全保）——独立于 T1 的 obs 冒号维度 | repair | w4 `relay/`（23 例「仅 exim 改写」组合） |

## X —— 信任差分（采信的身份/实例/结果不同 → 安全结论翻转）

| ID | 原语 | 根因 | 证据 |
| --- | --- | --- | --- |
| X1 | 重复 From 实例选择：perl/go 自底向上 vs dkimpy/rspamd 直接 fail | normalization | w1 `causal/` |
| X2 | U-label 评估器分裂：OpenDMARC none vs rspamd REJECT（CVE-2026-100891 核心，独立复现） | normalization | w2 `eai/` A 线 |
| X3 | 执行翻转：同一欺骗信 A-label 550 / U-label 250 | trust-boundary | w2 `eai-enforce/` |
| X4 | 外域 AR 存活（本域被剥离、外域不剥）+ 下游渲染为可信徽章 | trust-boundary | w2 `arsurv/` |
| X5 | rspamd source 归因取顶部 Received from-clause，伪造链文件扫描可劫持；诚实中继后恢复 | trust-boundary | w1 `i2/` |
| X6 | 群组/domain-literal From 使 rspamd DMARC 静默（OpenDMARC 同信正常 fail） | normalization | w2 `void/`、`hdrfuzz3/` |
| X7 | **注入的第二 DKIM-Signature 实例（畸形）→ 2v2 分裂**：dkimpy+rspamd fail vs perl+go pass | normalization | w4 `sign/`（15 例） |
| X8 | **perl 落单 parse-error**：同注入族，dkimpy+go+rspamd pass、唯 perl 拒解析（容错位置不同轴的镜像形态） | tolerance | w4 `sign/`（13 例） |

（w4 另注：rspamd 在 T2 的跨路径翻转中同样翻转判定——X 族与 T 族的链式组合新数据点。）

## D —— 展示/消费差分（最终呈现给用户或下游系统的身份不同）

| ID | 原语 | 根因 | 证据 |
| --- | --- | --- | --- |
| D1 | 同一突变体 Roundcube 显示底部实例（Author）、SnappyMail 显示顶部（Attacker） | normalization | w1 `causal/` + `clients/` |
| D2 | A-label/NFC/NFD 三形态全部渲染为受害者 Unicode 品牌 | normalization | w2 `display/` |
| D3 | ENVELOPE 取首元素、SEARCH HEADER FROM 为 any-instance 语义 | normalization | w2 `exec/` |
| D4 | rua 聚合按 pdomain 分组，U-label 事件结构性缺席 | normalization | w2 `rua/` |
| D5 | **Dovecot ENVELOPE 占位语义**：不可解析 From → `missing_mailbox@missing_domain` / `X@syntax_error` 占位或部分解析；from_group 可把多段 From 合并成 7 元素组（模板真值为末元素）——与 D3（实例选择轴）不同轴 | normalization | w4 `imap/`（12 例） |

## 与 SYNTHESIS 三级结构的映射

`SYNTHESIS.md` 的 L1（识别）= 本表 P；L2（解释）= T + X；L3（决策）= X + D。TAXONOMY 是可枚举的攻击原语视图，SYNTHESIS 是层级叙事视图，两表互为索引。

## 维护规则

- gramfuzz campaign 的新发现先机器归系列（`gramfuzz/funnel.py: classify`），root_cause 人工判定后入本表，编号接续。
- 纯 P（仅 parser 不一致、无下游后果）不入本表——它是 stage1 素材（`stage1.json`），不是攻击原语。
- 阴性结果（如 guided.case-name 全被语义去重吸收）记入 campaign RECORD，不在此表。
