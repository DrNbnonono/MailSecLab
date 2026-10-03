# RECORD —— gramfuzz 首轮全量 campaign（任务 7）

run：`results/research/w4-20261003a/gramfuzz/`，2026-10-03。
引擎：`/mnt/e/Gramfuzz`（独立仓库，本 campaign 代码版本 = commit `5d3d93c`，本地提交未 push）；
计划 `E:\Gramfuzz\docs\PLAN-gramfuzz.md` 任务 7。
栈：研究网（msl-auth-postfix / exim / opensmtpd / msl-mailpit / msl-dovecot），捕获路由三处手术按
`SURGERY.md`（本目录）在位，campaign 后已按同文件回滚。

## 1. 漏斗数字

| 层 | 数量 | 说明 |
| --- | --- | --- |
| corpus | **39,000** | 13 入口 × (fresh 1500 + mutated 1500)，`CORPUS_SEED=20261003` 固定可重放；`--smoke` 小轮（390）已快照进 `smoke-snapshot/` |
| stage1 survivors | **10,119**（26.0%） | 三 parser（python email / Go net/mail / Node mailparser）判定元组不一致 |
| stage2 入选 | **236** | 语义去重（entry × views 元组集合）后 236 < cap 400，**未触上限**，无抽样丢弃 |
| 中继臂 | 236×3 | postfix 235 捕获 / exim 235 / osmtpd 163（73 封 `550 5.7.1 not RFC 2822 compliant` 拒收，1 封 corpus_check 门槛拦截） |
| 签名臂 | 100（+KB2 锚） | 锚精确复现（file: dkimpy=parse-error / perl+go+rspamd=pass；postfix 路径全 pass） |
| 消费臂 | 40 | 40/40 投递，9 例 X-Case-ID 沉正文（locator=body），12 例 ENVELOPE≠头区第一 From |
| **candidates** | **150**（全部 `lab_confirmed=true`） | 86 条纯 P 留在 stage1.json 不进 candidates（计划判定规则） |

## 2. 系列分布（stage2 236 行，counts 按字母计）

| 链 | 行数 | 其中进 candidates |
| --- | --- | --- |
| P（纯） | 86 | 0 |
| P+T | 111 | 111 |
| P+X | 8 | 8 |
| P+D | 0 | 0 |
| P+T+X | 19 | 19 |
| P+T+D | 0 | 0 |
| P+X+D | 0 | 0 |
| P+T+X+D | 12 | 12 |
| **合计** | **236**（T=138, X=39, D=12, U=0） | **150** |

候选按入口：obs-from 24、from 16、obs-received 14、return-path 14、dkim-tags 14、arc-ams 11、
arc-aar 10、authres 9、received 8、reply-to 8、arc-as 8、sender 7、resent-from 7。
候选按算子：tab-colon 39、byte.flip 34、line.del 31、space-colon 18、fold-line 15、fresh(None) 4、
byte.delete 3、line.move 2、byte.insert 2、line.dup 1、dup-line 1。

T 的保留组合（postfix,exim,osmtpd）：仅 exim 改写 (T,F,T)=23；仅 postfix 改写 (F,T,T)=18
（经典 obs 冒号规范化）；三家全改 (F,F,F)=24；postfix+exim 改写且 osmtpd 拒收 (F,F,None)=49；
其余组合合计 24。

## 3. 新原语清单（与计划任务 8 的 19 条既有表对照）

> 本 RECORD 写作时 `results/research/TAXONOMY.md` 尚未落盘（并行任务在写），对照基线为
> PLAN-gramfuzz.md 任务 8 节的 19 条（P1-P5 / T1-T4 / X1-X6 / D1-D4）。以下只列**新**的；
> 编号建议按任务 8 规则接续（T5+、X7+、D5+），root_cause 为本 RECORD 的建议、终判在任务 8 人工。

### 新 1（建议 T5+X 链）：mbox `From ` 行歧义 → Postfix 抬升 X-Mailbox-Line 并终结头区

**触发字节**：首行头字段名为 `From` 后跟**空格**（mbox From_ 行形状）再跟 WSP 与冒号，
如 `From \t:"`、`From :,\r…`（7 例，全部 obs-from 入口）。
**Postfix 行为**：把该行整行抬升为 `X-Mailbox-Line: From \t:"…` 头，**头区在该行终结**——其后
所有头（含 DKIM-Signature 与全部身份头）沉入正文；opendkim 加
`Authentication-Results: … dkim=permerror`，rspamd 加 `X-Spam: Yes`（score 17.0）。
**下游后果**：文件级 dkimpy=tool-error / perl+go+rspamd=pass；过 postfix 后 perl/go/rspamd=
none（`signature_count: 0`）而 dkimpy=fail——同一信两路径四种命运。
**最小对立对**（同一入口同一天）：`gf-obs-from-fresh-0002`（`From \t:"`，空格）→ 抬升+沉没；
`gf-obs-from-fresh-0000`（`From\t\t\t:`，仅 tab）→ 无 X-Mailbox-Line，DKIM 留头区，From 被规范
化为 `From:`。**一个字节类别（空格 vs tab）翻转 Postfix 的整个处理路径。**
证据：`sign/gf-obs-from-fresh-000{0,2}-sign.*`；7 例清单见 candidates.json（file.dkimpy=
tool-error 的 7 条）。root_cause 建议：repair（与 T2「修复决定判决」同族，但触发与机制字节
均为新：X-Mailbox-Line 抬升是本实验室首次观测）。

### 新 2（建议 X7/X8）：畸形第二 DKIM-Signature 实例的四验证器新分裂形态

对有效签名之上注入**语法畸形的第二 DKIM-Signature 实例**（tag-list 文法垃圾）：

- **2v2 分裂**（15 例）：dkimpy=fail、rspamd=fail vs perl=pass、go=pass——同一字节两两采信相反。
- **perl 落单**（13 例）：perl=parse-error（拒绝解析整信）、dkimpy=go=fail、rspamd=pass。
- 文件级与 postfix 路径判定相同（gen_preserved=True，非变换伪影）。

与既有条目的关系：KB2/任务 6 锚是「obs **Received** 注入 → dkimpy 拒解析、其余 pass」；X1 是
「重复 **From** 实例选择」。本条是**被注入实例本身即 DKIM-Signature** 时的实例/畸形处理分裂，
perl 落单与 rspamd 单独 pass 的形态均未见于 19 条表。root_cause 建议：normalization（实例选择
与容错的组合）。

### 新 3（建议 T6）：Exim 尾部空白折行丢弃（独立于 obs 冒号改写的第二种改写微机制）

Exim 对生成头的**前段逐字节保留**、但丢弃**尾部纯空白折行**（`…:27GMT \r\n` 之后的
`\r\n \r\n\t  \r\n` 类空折行）；postfix/osmtpd 逐字节保留。字节级对照：
`relay/{postfix,exim,osmtpd}/gf-received-guided.tab-colon-0011.stored.raw`（111B 生成头，
postfix/osmtpd 全保、exim 尾折丢失）；ARC 头同机制
（`gf-arc-aar-guided.tab-colon-0020`）。既有 T1 是「obs 行字节的改写 vs 保留」；本条是
**尾部空白折行**这一独立维度（23 例仅 exim 改写的组合即由此而来）。root_cause 建议：repair。

### 新 4（建议 D5）：Dovecot ENVELOPE 对不可解析 From 的占位语义与实例合并

12 例 D 的 env 形态：`missing_mailbox@missing_domain`（占位）或 `<局部垃圾>@syntax_error`
（部分解析），对照头区第一实例抽取的垃圾串——**IMAP 消费者看到的发件人既不是攻击者注入值
也不是模板值**。其中 `gf-obs-from-fresh-0000` 的 ENVELOPE from_group 把多段 From 内容合并成
**7 元素地址组**（含模板真值 `security@lab.test` 为末元素），from_slot 取首元素占位符。
与既有 D3（ENVELOPE 首元素 vs SEARCH any-instance）不同轴：本条是**不可解析输入的占位/部分
解析语义**。root_cause 建议：normalization。

### 复现既有条目（引擎对已知原语的自动化复现，不编号）

- **T1**：`gf-obs-received-fresh-0001`——postfix 把 `Received :(` 规范化为 `Received:(`，
  exim 逐字节保留（w3 diffrun 捕获臂结论的语法引擎复现）。另观测到 T1 机制**扩展到身份头**：
  postfix 亦把 `From\t\t\t:` 规范化为 `From:`（gf-obs-from-fresh-0000，imap 存档）。
- **T2/KB2 跨路径翻转**（4 例）：file dkimpy=parse-error / perl+go+rspamd=pass → postfix 路径
  dkimpy=fail、**rspamd 也翻为 fail**（rspamd 翻转是 KB2 之外的新数据点，归入 T2 家族）。
- **P4 一般化**：parser 三命运（python 头区死亡 / go 全存活 / node 计入）从 Received 八形态
  扩展到全部 13 个入口族（from/obs-from/sender/reply-to/return-path/resent-from/authres/
  dkim-tags/arc-*）。

## 4. 阴性面

- **无零差分入口**：13 个入口在 stage1 全部有幸存者、在 stage2 全部有候选。最小的是
  sender/resent-from（各 7 候选）。
- **算子幸存率**（stage1，survivors/total）：space-colon **2060/2060=100%**、tab-colon
  **3142/3142=100%**（obs 冒号类必差分）；fold-line 18.3%、line.del 23.9%、byte.flip 24.8%、
  byte.insert 22.6%、byte.delete 16.5%；最弱：fresh 12.3%、case-name 12.3%、dup-line 12.7%、
  line.dup 14.1%。
- **guided.case-name 零 stage2 行**：212 个幸存者全部被语义去重吸收（其 views 形态与其他算子
  重合），**这是去重层面的阴性，不是 stage2 实测阴性**——不得写成「case-name 无下游差分」。
- **X 只在 from / obs-from / dkim-tags 三个入口出现**（各 13）；sender、reply-to、
  return-path、resent-from、authres 的签名臂样本判定全一致（无分裂）。
- **D 只在 from(8) / obs-from(4) 出现**；sender、reply-to、resent-from 的消费臂样本无不一致。
- **U=0**：236 行全部至少带 P。
- **osmtpd 拒收 73/236（31%）**：`550 5.7.1 ... not RFC 2822 compliant`——其容错边界本身
  与 postfix/exim 不同（已知现象，本 campaign 量化了比例）。
- **消费臂 mismatch_approx=0**：D 归一化修正（任务 7.0）在本轮 40 例抽样中未捕获仅空白差异
  （smoke 轮为 2/14）——修正为防御性修复，不改变本轮 D 计数。
- 优先级反馈落盘 `weights.json`：line.del/line.move/tab-colon/dup-line 顶到 8.0 上限，
  space-colon 回落到 3.27（45 行中 27 纯 P，惩罚多于奖励），byte.insert 0.9 / byte.delete 1.15
  被压低。

## 5. 判定规则与证据链实现（`--phase report`）

`lab_confirmed=true` = 系列含 T/X/D 之一 **且** 四件套齐全（全部磁盘核验，缺件记
`missing_evidence` 不静默）：①输入 eml+sha256（重算哈希对 corpus-index）；②SMTP 转录
（T→中继臂逐目标、X→签名臂、D→消费臂）；③存档 raw（同臂）；④臂输出（X→四验证器判定、
D→ENVELOPE 记录、T→逐目标保留判定，锚在存档字节）。纯 P 留 stage1.json 不进 candidates。
`root_cause` 置 null——根因为人工判定（任务 8）。本轮 150 候选四件套全齐。

## 6. 人工抽样复核（任务 7.2）

- 机器侧（`review_sample.py`，seed=7）：分层（按系列链）抽 **31/150 = 20.7%**，逐例重算
  sha256 / gen-in-stored / 中继标记 / 定位键 / 验证器重跑 / ENVELOPE 重算——**0 例不一致**。
- P+T 层机器抽样 22/111=19.8%，补人工字节级 1 例（`gf-obs-received-fresh-0001`）达
  23/111=20.7%。
- 人工深查 5 例（T / ARC-T / X / 全链 D / 补样 T1）字节级确认差分真实，非 fetch 伪影。
- **D 新鲜度核对**：12 个 D 例 imap 存档顶部 Received 时间戳全部为本轮 13:11-13:12 UTC
  （smoke 为 11:25-11:51 UTC），排除 w3 式同 X-Case-ID 旧信抓取。
- **review_flag：0**。复核记录与深查细节在 `review.json`（含给审阅者的三条注意事项：
  exim 尾折丢弃微机制、relay/sign/imap 目录残留 smoke 轮未重选 case 的旧文件——候选证据
  路径全部由本轮行驱动、构造上不受污染、但逐文件审阅时需区分、以及 Dovecot 占位符语义）。

## 7. 仪器与门槛记录

- 开跑前控制信 N=1 × 3 目标全部 captured（存档 1004/799/812 B，与 SURGERY.md 记录一致）；
  KB2 锚 PASS；stage2 签名臂内锚再次复现。
- 全程 attribution_bad=0（中继标记核对 + 标记感知恢复抓取，混合主题形态以 ok-recovered 记）。
- 保活按 SURGERY.md 重启过一次（首轮保活进程被外部终止，stage2 期间重启，无停机影响）。
- corpus 生成 39,000/39,000；stage1 三探针覆盖 ≥95% 门槛通过；1 例 corpus_check 拦截
  （`gf-received-byte.insert-0116` bare LF，三目标一致拦截，记 problems 不记阴性）。
- phase 日志：`corpus/stage1/stage2.phase.log`；启动器 `run-phase.sh`（nohup 长跑纪律）。

## 8. 与计划的偏差

1. run_id 为 `w4-20261003a`（计划示例写 w4-20261005a，按实际执行日期）。
2. 入口 13 个而非计划示例的 11（任务 3 执行时 ARC 拆为 aar/ams/as 三入口），全量 39,000 文件。
3. 代码侧三处改动（E:\Gramfuzz 仓库，已提交）：report phase 实现；D 归一化修正
   （`_fold_wsp`/`_display_approx`，仅空白差异不算 D）；`_dedup_and_cap` 混型排序崩溃修复
   （>cap 首跑才触发：views 元组经 JSON 往返后 ("error",) 与 (0,True,5) 不可比，改 json.dumps
   规范化键，附回归测试）。
4. stage2 after_cap=236 < 400：语义去重后唯一形态 236 种，上限未触发，无抽样丢弃。
5. T 行四件套的第四件按「臂输出」落地（T 的中继差分输出=逐目标保留判定+存档），X/D 分别为
   验证器/消费输出——判定规则原文的工程化解释，见第 5 节。
6. Mailpit 在开跑前清空一次（控制信与 KB2 预检后，存档已落盘）；campaign 中未再清空
  （fetch 窗口 50 条 + 0.8s 间隔下无积压问题，attribution_bad=0 佐证）。

## 9. 产物清单（本目录）

`corpus/`（39,000）、`corpus-index.json`、`stage1.json`、`stage1-summary.json`、
`survivors.json`、`stage2.json`、`stage2-summary.json`、`weights.json`、`candidates.json`（门）、
`review.json`、`RECORD.md`（本文件）、`relay/{postfix,exim,osmtpd}/`、`sign/`、`imap/`、
`calibration.json` + `calibration-corpus/`（w3 六锚）、`smoke-snapshot/`（smoke 轮 JSON）、
`run-phase.sh`、`review_sample.py`、`*.phase.log`、`surgery/`（SURGERY.md、配置备份、控制信）。

## 10. 4-5 号工作门状态

`candidates.json` **非空（150 条，全部 lab_confirmed=true，证据四件套磁盘核验齐全）**，
人工抽样复核 0 flag。**门条件满足；真实服务验证（4）与披露（5）是否开闸由负责人决策，
未授权不执行。**
