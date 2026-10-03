# U-label 机制与 Chen 2020 §4.2 的精确差异声明

> **状态更新（2026-10-02）**：上游核查发现 **CVE-2026-100891**（2026-09-28，Weitong Li 经 VulDB）已覆盖本机制的核心（OpenDMARC U-label 绕过、rspamd 差分、合法 IDN 假阴性）。本文档的对照分析仍有效，但「新机制」表述撤回；与该 CVE 的精确关系、我们仍持有的增量、以及 NFD 阴性结果见 **`UPSTREAM.md`**。

对照文本：`references/markdown/2020-Usenix-Chen_Composition_Kills_Email_Sender_Authentication.md` §4.2「Ambiguous domains」（A3，NUL ambiguity）；关联 §4.1 A1（non-existent subdomains）、A2（empty MAIL FROM）。本实验室证据：本 run `eai/`、`eai-enforce/`、`qname/fwd.log`、`exec/`。

## 一句话差异（中文）

Chen 2020 的 A3 利用**畸形 ASCII 输入里的元字符**（NUL 等）让两个组件对同一字符串**终止于不同位置**，从而使 DNS 查询落进攻击者控制的区、取回**攻击者选择的内容**完成伪造「pass」；本 run 的 U-label 机制里输入是**完全合法的 EAI 邮件**（RFC 6532/SMTPUTF8 语义下无任何畸形字节），分歧来自一条**规范强制要求的状态转换**（Author Domain 的 U-label→A-label 归一化，RFC 9989 §5.3.1 / RFC 8616）在维护版评估器 OpenDMARC 1.4.2 中**缺失**，其策略查询发出注册体系结构上不可能存在的原始 UTF-8 qname（注册机构只注册 A-label），于是**永远 NXDOMAIN**——攻击面不是「攻击者控制的内容」，而是**策略与报告的结构性缺席**本身。

## One-sentence delta (English, paper-ready)

Whereas Chen et al. (USENIX Security '20, §4.2) exploit malformed ASCII domain strings whose metacharacters (e.g., NUL) make two components terminate the *same* string at different offsets, so that the DNS fetch lands in an attacker-controlled zone and returns attacker-chosen content, our mechanism requires no malformed input at all: the message is a fully standards-compliant internationalized email, and the divergence arises from the *absence of a specification-mandated normalization step* — the U-label-to-A-label conversion of the RFC5322.From domain required by RFC 9989 §5.3.1 — in a maintained, deployed DMARC evaluator (OpenDMARC 1.4.2), whose policy query therefore emits a wire-format qname containing raw UTF-8 label octets that the registration system structurally cannot publish, yielding permanent NXDOMAIN; the exploit primitive is not attacker-controlled policy content but the *structural absence* of both enforcement and reporting.

## 逐维度对照表

| 维度 | Chen 2020 §4.2 A3（NUL ambiguity） | 本 run U-label 归一化缺失 |
| --- | --- | --- |
| 输入合法性 | 畸形：域名/tag 含 NUL 元字符 | 合法：RFC 6532 EAI 邮件，无畸形字节 |
| 歧义来源 | 低层字符串终结语义差异（C vs Perl/PHP），同一字符串不同截断 | 规范强制转换（U→A）在某一评估器中缺失；两个评估器对同一合法输入执行不同变换 |
| 作用对象 | MAIL FROM / DKIM d=、s= 构造的查询名 | DMARC 的主标识 RFC5322.From（Author Domain），外加对齐与 rua 报告 |
| DNS 落点 | 攻击者控制的区（内容可选） | NXDOMAIN（结构性不存在），无任何内容被取回 |
| 攻击原语 | 注入式：取回攻击者选择的内容伪造 pass | 缺席式：策略不被咨询、报告不生成 |
| 直接后果 | 伪造 dkim=pass + dmarc=pass | (a) 执行空洞：p=reject 从不生效（x1 550 vs x2 投递的决策翻转）；(b) 报告空洞：rua 聚合看不到事件（本 run rua 实验补证）；(c) 假阴性：合法签名的 IDN 邮件 dmarc=none（a1-ulabel-from-idnd） |
| 组合形态 | 单服务商内部组件不一致 | 同一条维护版链内两个 DMARC 评估器结论相反（OpenDMARC `none` vs rspamd `REJECT`，z14/z15） |
| 规范锚点 | 无（行为分歧本身） | RFC 9989 §5.3.1（2026-05， MUST 语义的 U→A）、RFC 8616/5890；§11.5 将「Denial of DMARC Processing Attacks」列为关注类 |
| 缓解面 | 修复后未见回归报告 | rspamd 3.4 做 U→A（会给出 REJECT），但其 `INVALID_FROM_8BIT` 启发式只反应 8-bit 字节；OpenDMARC-only 栈无任何一层 |

## 相邻但不等同的 Chen 机制（防审稿混淆）

- **A1（non-existent subdomains）**：SPF 与 DMARC 对「查哪个标识」分歧（MAIL FROM vs HELO），攻击者选不存在的子域制造「无 SPF 策略」——目标标识与机制均不同；A1 不涉及 RFC5322.From 的归一化，也不产生报告空洞。
- **A2（empty MAIL FROM）**：括号元字符使 SPF 视为空地址——仍是 ASCII 畸形输入家族。
- **§4.3 AR 注入（A4/A5）**：`legit.com(.attacker.com` 类元字符域让 DMARC 解析 AR 注释取错对齐域——同样是畸形 ASCII + 注入式。
- **§5.1 A7/Fig6c（空白包围 From、Fastmail 转发规范化）**：空白 obs 语法与转发改写——ASCII 语法层；本 run 的 A-3（8-bit 字段名终结头区）与它们同族，不作为新机制主张，只作背景。

## 证据指针

- qname 字节：`qname/fwd.log`（`_dmarc.` + label `6dc3bc6e6368656e`，两次）；rspamd 对照查 `xn--mnchen-3ya`：`qname/dns-queries-tail.log`、LAB_JOURNAL 14:10:28 条目。
- 决策翻转：`eai-enforce/`（x1 `550 5.7.1` vs x2 250 投递）。
- 评估器分裂：`exec/` z13-z16（OpenDMARC AR `dmarc=none` vs rspamd `DMARC_POLICY_REJECT`，同一 qid）。
- 假阴性：`eai/eai-a1-ulabel-from-idnd.stored.eml`（dkim=pass + dmarc=none）。
- 诚实边界（rspamd 启发式拦截）：`exec/` z10/z11 的 554 与 LAB_JOURNAL B-1 节。
