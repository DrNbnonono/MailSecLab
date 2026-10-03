# w2-20261002a 实验日志

四条路线：A=EAI 身份绑定矩阵，B=执行型消费者（IMAP SEARCH/ENVELOPE、rspamd DMARC 模块、rua），C=d=/s=→qname 构造探针，D=组合审计积累。
签名密钥复用 w1-20261001a/keys（lab.test selector cal 已在 DNS 发布）。本目录证据优先级与 AGENTS.md 一致。

## 环境基线（2026-10-02）

- auth 链：msl-auth-postfix（smtpd_milters=OpenDKIM:8891→OpenDMARC:8893，virtual_transport=lmtp:msl-dovecot:24）
- OpenDKIM 为不带 libunbound 的 2.11.0（Nameservers 10.88.0.53，Mode v，AuthservID mail.lab.test）
- OpenDMARC 1.4.2（AuthservID mail.lab.test，RejectFailures false）
- Dovecot 2.3.19，protocols=imap lmtp，无 sieve 包；msl-dns RUN_ID=w1-20261001a
- rspamd 3.4 local.d/dmarc.conf enabled=false（待 B 线打开）
- postconf -n 未见 smtputf8_enable 覆盖，Postfix 3.7 默认 yes

## 日志

### 2026-10-02 A 线第一轮（eai/ 目录，7 例）

DNS 区新增：`xn--mnchen-3ya.lab.test`（= münchen.lab.test 的 A-label）SPF -all + DMARC `p=reject`，`cal._domainkey.xn--mnchen-3ya.lab.test` 发布 w1 公钥。信封统一 alice@lab.test → bob@lab.test，全部经 msl-auth-postfix。

**A-1（承重，绕过方向）**：From 写原始 UTF-8 U-label（`author@münchen.lab.test`）时：
- OpenDMARC 的策略查询 qname 带原始 UTF-8 字节（dnsmasq 日志两次 `<name unprintable>`，来自 10.88.0.42），不做 U→A 转换（RFC 9989 §5.3.1 要求）→ NXDOMAIN → `dmarc=none (p=none dis=none) header.from=münchen.lab.test`。
- 同一域名写 A-label：`dmarc=pass (p=reject dis=none)`——p=reject 被正确取得。
- **即：受害 IDN 域的 p=reject 对 U-label 形态的 From 完全不被查询。**
- Dovecot IMAP ENVELOPE 把 From 域以 `{17}münchen.lab.test` 原始字节返回——瘦客户端显示的就是受害者品牌形态，与策略层从未查询的是同一字节串。
- SMTP 侧：Postfix 3.7 未声明 SMTPUTF8/BODY 参数也接受 8-bit 头值（plain MAIL FROM，250 接受）。

**A-2（假阴性方向）**：合法 IDN 邮件（From U-label、DKIM 以正确 A-label d= 签名、密钥发布在 A-label 区、OpenDKIM dkim=pass）同样 `dmarc=none`——对齐判定从未发生，受害域的 rua 监控被致盲。同一封信 AR 里出现 `header.from=münchen.lab.test`（UTF-8）与 `header.d=xn--mnchen-3ya.lab.test`（ASCII）两个「同一域名」的字符串形态。

**A-3（8-bit 字段名终结头区的全链传递）**：`X-Ünknow: one` 插在 DKIM-Signature 之后、被签字段之前：
- 文件级：dkimpy=parse-error / perl=pass / go=pass / rspamd=pass（分裂）。
- Postfix 收 250 并投递；cleanup 在无效字段名处**静默终结头区、不插空行**，From/To/Date/Subject/Message-ID/X-Case-ID 全部沉入正文（存档证实，头区只剩 DKIM-Signature + 中继头）。
- OpenDKIM（milter 看到的是 cleanup 后字节）：`dkim=permerror (bad message/signature format)`；OpenDMARC：找不到 From，不盖 AR；milter 时段 DNS 零查询。
- Dovecot IMAP HEADER.FIELDS(X-CASE-ID) 找不到该信（按正文 BODY 搜索定位到 uid 32）。
- 与 J3 同族但对象从 Received 换成任意 8-bit 名字段；网关 rspamd 文件扫描 pass 而接收端 OpenDKIM permerror 的分裂保留。

**A-4（ENVELOPE 层记录）**：Dovecot ENVELOPE 对 UTF-8 显示名/域用 IMAP literal 原样返回字节（`{6}作者`、`{17}münchen.lab.test`）；RFC 2047 编码词显示名原样保留不解码。Sender/Reply-To 槽位缺省复制 From 值。

### 2026-10-02 A 线第二轮：决策翻转 + qname 字节级证据（eai-enforce/、qname/）

**决策翻转对照（OpenDMARC RejectFailures=true，实验后已复原为 false）**：

| case | From 域形态 | DKIM | SMTP | AR dmarc |
| --- | --- | --- | --- | --- |
| x1-alabel-spoof | A-label xn--mnchen-3ya | 无 | **550 5.7.1 rejected by DMARC policy** | （拒绝于 DATA 后） |
| x2-ulabel-spoof | U-label 原始 UTF-8 | 无 | **250，投递进箱** | `none (p=none)` header.from=münchen… |
| x3-ulabel-spoof-signed-foreign | U-label | lab.test 签名（pass 但不对齐） | 250，投递 | none |
| x4-alabel-legit-signed | A-label | 受害域签名（pass 对齐） | 250，投递 | `pass (p=reject)` |

- 同一欺骗内容、同一受害域 p=reject、同一信封，唯一变量是 From 写 A-label 还是 U-label：**一个 550、一个进箱**。
- 诚实边界：RejectFailures=true 是 OpenDMARC 的严格模式；默认 false 下两封都投递，差别是 `dmarc=fail`（进报告/本地策略/评分）vs `dmarc=none`（对监控完全不可见）。**监控盲区方向与执行模式无关。**
- cases.json 里 before 记录为 true：第一次运行因脚本 bug 中断未走 finally，配置曾停留 true，属记录瑕疵，已如实保留。

**qname 字节级捕获（research/lib/dns_fwd.py，OpenDMARC 的 resolv.conf 临时指向转发器，实验后已复原并经 y3 健康探针验证）**：

- A-label 探针：`_dmarc.xn--mnchen-3ya.lab.test`（labels: `_dmarc` `786e2d2d6d6e6368656e2d337961` …）✓
- **U-label 探针：`_dmarc.` + 单个 8 字节 label `6d c3 bc 6e 63 68 65 6e`**（= `münchen` 原始 UTF-8，`c3bc` = ü），NXDOMAIN 后原样重发一次。
- DNS 线格式：label 内容为任意八位组在协议上合法，但注册机构只注册 A-label 形态 → 该 qname 结构上不可能命中受害者策略区。
- 事故记录：给 opendmarc.conf 误加 `Nameservers`（那是 OpenDKIM 的指令）导致容器配置错误退出（exit 78），已用 docker cp 修复；docker cp 写 resolv.conf 报 device busy，改用容器内重定向复原。

### 2026-10-02 B 线第一部分：DMARC 评估器分裂 + rspamd 接入（exec/ 目录）

栈变更（记录在案）：rspamd proxy worker（*:11332, milter=yes）挂入 auth-postfix 的 smtpd_milters 末位；启用 rspamd 的 spf 模块与 dmarc 模块（`no_reporting=true`，注意 `reporting=false` 是错误写法会使 dmarc.lua 初始化崩溃）；`local_networks` 收紧到 127.0.0.0/8（否则实验室 IP 全被当本地网络，SPF/DMARC 一律跳过）；actions reject=999（z13 起生效，为保投递取证据；z10/z11 在默认阈值下已被 554 拒，如实保留）。

**B-1（承重）：同一封邮件、同一条链、同一个 DNS，两个 DMARC 评估器结论相反**

| case | From | OpenDMARC AR（存档头） | rspamd 符号（扫描日志，同一 qid） |
| --- | --- | --- | --- |
| z13 A-label 欺骗 | xn--mnchen-3ya | `dmarc=fail (p=reject)` | DMARC_POLICY_REJECT |
| **z14 U-label 欺骗** | **münchen（原始 UTF-8）** | **`dmarc=none (p=none)`** | **DMARC_POLICY_REJECT{münchen.lab.test}** |
| **z15 U-label+外域签名** | 同上 | **`dmarc=none`** | **DMARC_POLICY_REJECT** + R_DKIM_ALLOW{lab.test} |
| z16 A-label 合法 | xn--mnchen-3ya | `dmarc=pass (p=reject)` | DMARC_POLICY_ALLOW |

- DNS 线级：z10/z11 时段 rspamd（10.88.0.30）查 `_dmarc.xn--mnchen-3ya.lab.test`（**做了 U→A 转换**）；OpenDMARC 同期查原始 UTF-8 字节 qname。
- 结论：**Author Domain 的归一化是评估器自定义的**——p=reject 是否被咨询取决于链里哪个组件做查询。OpenDMARC 1.4.2 的 AR 是「无策略」，受害域的 rua 聚合报告对这类欺骗不可见（监控盲区），而 rspamd 却能给出 REJECT。
- 诚实边界：rspamd 的 `INVALID_FROM_8BIT(6.0)+FROM_INVALID(2.0)` 内容启发式对 8-bit From 会加分（z10/z11 在默认阈值累计≥15 被拒）——**启发式反应的是「8-bit 字节」不是「身份绑定」**，且 OpenDMARC-only 栈（Postfix+OpenDKIM+OpenDMARC，无 rspamd）没有这层网。探针早期版本 header-To≠envelope-RCPT 引入 FORGED_RECIPIENTS(2.0) 伪影，z13 起已修正（To: bob@lab.test）。
- 附带：z1-z8 期间 rspamd 的 DKIM 对 U-label From 的原始字节哈希正常（R_DKIM_ALLOW），与四家文件验证器一致。

### 2026-10-02 B 线第二部分：Dovecot 服务端身份消费面（exec/imap-probe.json）

- **ENVELOPE 对重复 From 返回全部实例的地址列表**（物理顺序）。瘦客户端取首元素 → 顶部实例（uid 3→Attacker，uid 27→Author）。至此实例绑定矩阵：DKIM/OpenDKIM=底部，OpenDMARC=顶部，Dovecot ENVELOPE=首元素（顶部），Roundcube=底部（w1 证据），SnappyMail=顶部（w1 证据）。
- **uid 32（8-bit 字段名、From 沉正文）ENVELOPE 全 NIL**：瘦客户端显示「无发件人」。
- **SEARCH HEADER FROM 为 any-instance 语义**：服务端过滤/归档决策可被未验证实例驱动。
- **A-label 字符串搜不到 U-label 邮件**：`SEARCH HEADER FROM "xn--mnchen-3ya"` 只命中 A-label 邮件，U-label 欺骗信全部漏网；用户按注册形态搜索/过滤存在盲区。
### 2026-10-02 C 线：d=/s=→qname 构造探针（qname/ 目录，c1-c4）

全部用例 b= 对实验室密钥数学有效，公钥同时发布在 lab.test、evil.test、xn--mnchen-3ya.lab.test 三个区。观测：四家文件验证器 + 链上 OpenDKIM 的 AR（含 header.d 选择）+ OpenDMARC 对齐。

| case | d=/s= 形态 | dkimpy | perl | go | rspamd | 链上结果 |
| --- | --- | --- | --- | --- | --- | --- |
| c1 大写 | d=LAB.TEST; s=CAL | pass | pass | pass | pass | dkim=pass header.d=LAB.TEST（大小写保留进 AR）；dmarc=pass |
| c2 尾点 | d=lab.test. | **tool-error** | pass | pass | pass | **dkim=pass header.d=lab.test. 但 dmarc=fail** |
| c3 d= 内 FWS | d=lab␍␊⇥.test | **fail** | **parse-error** | **pass** | **none** | dkim=pass（OpenDKIM 剥 FWS）；dmarc=pass |
| c4 重复 d= | d=lab.test; d=evil.test | **fail**（拒重复 tag，合 RFC 6376 §3.2） | pass | pass | pass | **dkim=pass header.d=evil.test**（取最后一个 d=）；dmarc=fail（From=lab.test 与 evil 不对齐） |

- **c2 是链内自分裂**：OpenDKIM 用带尾点的 qname 取到密钥（DNS 把 `lab.test.` 当同一区）判 pass，OpenDMARC 拿 `header.d=lab.test.` 与 `header.from=lab.test` 做字符串比较判不对齐 → **同一封信同一条链 dkim=pass + dmarc=fail**。方向是假阴性（合法信被 DMARC 拒），不是绕过。
- **c4 是密钥层身份绑定分歧**：OpenDKIM/perl/go/rspamd 对重复 d= tag 各取其一（OpenDKIM 取最后一个并以该域出 AR），dkimpy 按 §3.2 拒绝。同一签名字节被绑定到不同域名；AR 声称的签名域取决于验证器实现。
- c3 四家全不一致（fail/parse-error/pass/none）。
- 待补：c2/c3/c4 的逐家 qname 字节归属——受 msl-dns 容器时钟比宿主慢约 25 分钟影响，`--since` 窗口错位（改按 qname 模式捞日志可见 evil.test 查询批来自 10.88.0.20/.30/.41）。下次用 dns_fwd.py 转发器对逐家重跑即可。
- 新想法（记录）：尾点/大小写形态进入 AR 后，AR 消费者（MUA、报告器、下游对齐器）是否做域名归一化是又一层未测边界；c1 显示 OpenDKIM 把 `LAB.TEST` 原样写进 AR。

### 环境备忘（2026-10-02 收尾时）

- 栈变更持久项：auth-postfix `smtpd_milters` 末位新增 `inet:msl-rspamd:11332`；rspamd 启用 spf/dmarc 模块、`local_networks=127.0.0.0/8`、actions reject=999（add_header=6）；msl-dns extra-dns.conf 新增 IDN 受害域与 evil.test 的记录。恢复默认栈时按本节回滚。
- msl-dns 容器时钟漂移约 -25 分钟（14:18 重启后出现），影响 docker logs --since 归属，改用 qname 模式匹配或转发器探针。

### 2026-10-02 重大定位修正：U-label 绕过已有 CVE，发现权不是我们的

上游核查（任务一）发现：**CVE-2026-100891**（PUBLISHED 2026-09-28，CNA=VulDB，报告人 Weitong Li，exploit 公开）：OpenDMARC ≤1.4.2 `opendmarc_policy_query_dmarc` 不做 U→A 转换（CWE-172，CVSS 7.3），与我们 w2 实验同构。原文 weitongli.com/share/opendmarc-ulabel-not-converted.html 的覆盖面（测试于 2026-07-28/30）：

- **已覆盖**：U-label 绕过（p=reject 与 p=quarantine）、拉丁/CJK/西里尔多文字、OpenDMARC vs rspamd 评估器分裂、合法 IDN 邮件假阴性、UTF-8 原样发布 _dmarc 节点也无效（归一化缺失在 DNS 匹配之前）、根因定位 RFC 7489 §6.6.1 的 ToASCII 缺失。同一研究员同日报了 CVE-2026-101014（cleanup 越界读）。
- **明确未覆盖（我们的独有增量）**：rua 聚合报告空洞（我们已有 HistoryFile `rua -` 直接证据）、NFD/规范形变体、IMAP/ENVELOPE/SEARCH 服务端消费面、MUA 显示层、rspamd 以外评估器、quarantine 之后的下游执行。
- 结论：NOVELTY_CLAIM.md 的「新机制」表述撤回，改写为「与 CVE-2026-100891 的关系与增量」。论文故事转向：对刚披露缺陷在真实接收栈中的**系统性影响面表征**（报告空洞、消费面盲区、显示层）+ NFD 变体若成立则是**超出 CVE 范围的新变体**。
- 环境佐证：上游休眠（1.4.2 后无发布，厂商对 CVE 无回应），发行版仍在打包（Fedora 1.4.2-33、Debian 1.4.2-5.1 等）——存量暴露持续。
- 容器内二进制核查：`libopendmarc.so` strings 无任何 idna/idn2/punycode 痕迹——IDN 处理在库层面不存在。



### 2026-10-02 转向：新机制猎取（CVE 后时代）

U-label 核心已 CVE 化，转入自由探针模式。本轮三个快探针 + 一个检索方向：

- **ar1 AR 注入**：OpenDMARC 配置 `TrustedAuthservIDs mail.lab.test`（信任边界靠 authserv-id 字符串匹配）。伪造 `Authentication-Results: mail.lab.test; dkim=pass header.d=<受害域>` 的无签名欺骗信能否得到 dmarc=pass？民间文献（StackExchange 2020）说当年可行，维护版现状未测。
- **ar2 AR 注释分裂（Chen A4 回归审计）**：d= 带元字符（`(`），OpenDKIM 查攻击者区验签 pass、AR 里 header.d 带元字符原串，OpenDMARC 的 AR 解析若按 RFC 8601 注释语法取值则对齐受害域 → 无密钥欺骗任意 ASCII 域（不限于 IDN）。Chen 2020 在服务商测过、称已修；开源栈现状未测。
- **ar3 徽章伪造**：SnappyMail 读 AR 显示 DKIM 状态（w1 见过红叉）——伪造 AR 是否显示绿勾（Roundcube w1 记录不显示认证状态，作对照）。
- 检索：DMARC rua 报告消费端（parsedmarc 等）的伪造报告投毒有没有先例。

判据：ar1/ar2 的阳性=「默认自建栈上零密钥、任意 ASCII 域的 DMARC pass」；阴性则记录为修复确认。ar3 阳性=显示层信任指示器可注入。

### 2026-10-02 hdrfuzz：邮件头差分模糊测试工具 v1（参考 REQSMINER/Inbox Invasion/Andarzian）

**动机**：战役 V 用手工文法案例一天内找到了 rspamd 群组静默等新分裂，而 w1 第 4 周 fuzz 零新发现——差距在（a）生成轴缺 From 地址形文法（群组/domain-literal/obs/EAI），（b）oracle 只有四家文件验证器，没有链上判定（OpenDMARC AR、策略是否被咨询、投递、ENVELOPE）。w1 fuzz.py 的 `chain` 方法实际未接链（else 分支退化为 syntax 插入）。

**设计**（对照三个参考系）：REQSMINER 借「文法生成+变换前后状态」→ 我们生成 From 形文法×身份字段组合、观测链前后；Inbox Invasion 借「AST/结构生成+端到端 oracle」→ oracle 扩到 AR 盖章/策略咨询（DNS 线）/投递/ENVELOPE；Andarzian 借「差分判定+最小化」→ 分歧签名去重 + 已知类种子（战役 V 结果编码为 known，新类才计数）+ 等预算消融（byte+文件 oracle vs 文法+链 oracle）。

**分歧签名**（安全相关派生值，非字节）：`policy_split`（OpenDMARC 咨询策略 XOR rspamd 有 DMARC 符号）、`ar_identity`（header.from 域类别 vs ENVELOPE 域类别不一致）、`no_stamp`（投递但无 OpenDMARC AR）、phase2 的 `verdict_split`（签名件四家分裂）。

**栈变更记录**：rspamd `local.d/asn.conf enabled=false`（ASN 查询本被黑洞，仅延迟无判定；单案例 10s→亚秒）。

### 2026-10-03 Resent/Sender 显示绑定探针（resent/）——干净阴性

- 修复自身 bug：resent_probe 的 From 行漏 CRLF 导致 From+To 粘连（与 sig_probe 首跑同族错误，两处均已修；教训：字段替换/拼接必须显式带行尾）。
- 修复后五例（Resent-From 受害域/obs/U-label、Sender 受害域、对照）：**Roundcube 与 SnappyMail 的列表和详情全部只绑 From**（rsc1-3 详情均为 `From Attacker <attacker@evil.test>`），Resent-From/Sender 不构成显示替代原语——与 Chen A8 的「From 缺失时才显示替代头」一致，From 存在时无替代。阴性记录。
- 首部 Resent-From 不触发 Postfix 的 X-Mailbox-Line 改写（存档字节核对）。

### 2026-10-03 hdrfuzz3 千例扫描（hdrfuzz3/，3×300 并行，476s/worker）

**规模**：900 新例（累计本 run 约 1200 例）。新轴：AR 形态 × Reply-To 形态 × Sender 形态 × From 池；oracle 增 `ar_surv`（伪造 AR 存活）与 ENVELOPE 槽位。

**AR 存活规律（千例级精确刻画）**：本域 authserv-id（mail.lab.test）**0/157 存活**（全剥）；**外域 id 630/630 全存活**——含 `dkim=pass`、`dkim=fail`、**`dmarc=pass (p=reject)`（比 dkim 徽章更强的声明）**、obs 冒号形态。剥离规则=「仅删声称本域 id 的行」，在 900 例上无一例外。
- 组合意义：SnappyMail 徽章伪造（arsurv b1 端到端）对**任意外域 id、任意 obs 形态**都成立；伪造 `dmarc=pass` 行同样可达邮箱（渲染端取哪一行待测）。

**domain-literal 是双评估器空洞（新统计发现）**：rspamd 静默构成 = dl-victim 139 + group 117 + obs 14。domain-literal 此前只证 OpenDMARC 空洞（v3），现证 **rspamd DMARC 同样静默**——与群组并列的第二个双空洞形态，139 例支撑。

**Reply-To 双实例**：Dovecot ENVELOPE 多数返回全部实例（dup-evil-victim 130/156 both）——回复目标绑定由客户端自选，thin-client 取首元素即攻击者可控。待办：Roundcube/SnappyMail 的回复目标测试（w1 只测过单 Reply-To）。
- 统计注意：victim 检测用整串子串、不区分槽位，`env_victim` 列有 From 槽串扰，只作粗信号。

**家族分布（900 例）**：M6 正常 519 / OpenDMARC 空洞 250 / rspamd 静默 117 / 无盖章 14——与 240 例时的比例一致，家族集合稳定。

### 2026-10-03 parsedmarc 安装阻塞确认

`pip3 install --break-system-packages parsedmarc` → "from versions: none"（PyPI 不可达）。报告消费端脉继续被离线环境阻塞，需有网窗口装包或离线塞 wheel。

### 2026-10-03 exim 镜像修复 + 三列矩阵完成（repair/facts.json）

**exim 三层根因与修复**（收到「构建正确的镜像」指令）：① 入口 `-C` 覆盖配置→投递子进程非 root 传 -C 丢权限——修法=配置放编译期默认搜索路径 `/etc/exim4/exim4.conf`（root:root 644）、入口改 `exec /usr/sbin/exim -bdf`；② transport `to_mailpit` 写死 `port=1025`——改 25；③ `docker commit` 继承临时容器的 entrypoint 覆盖——用 `--change "ENTRYPOINT"` 恢复。产出正确镜像 `received-lab-exim:v3`（配置+入口修复），容器双网（旧 mailnet + 研究网）。
- 调试教训：docker cp 传入文件属主=源属主（非 root）会触发 exim 配置信任检查；commit 会带走过往的 entrypoint/cmd 覆盖。
- 通链验证：队列冲清、postfix 收到 from exim 连接、11 探针投递+存档 11/11。

**三列矩阵结论（facts.json）**：
- **obs-top 位置依赖修复的跨 MTA 普适性**：直投 From 消失（fC=0/X-Mailbox-Line/permerror/无章），经 exim 或 opensmtpd 一律恢复（fC=1、dmarc=fail）——任何在头部插入 Received 的中继都破坏「首字段」前提。
- **空洞类性质对两种异构中继免疫**：U-label none/群组 fail+静默/字面量 none/重复 From fC=2/**外域 AR 存活 ar=T×3**/obs 签名存活 pass×3。
- bit8 经 exim 出现 dm=fail（有章）——direct/osmtpd 的判定待补算进 facts（头区终结现象本身已记）。

### 2026-10-03 攻击 1：异构 MTA 修复矩阵（repair/）——L1 框架首个实例

**部署**：旧栈 exim 4.96 / opensmtpd 6.8 接入研究网、下一跳改 msl-auth-postfix（字节级改配置+重启；opensmtpd 成功，exim 见下）。11 个单跳性质探针 × {direct, exim, osmtpd}。

**核心发现（协议层机制）——头部位置是不被跟踪的跨组件状态，而修复行为依赖它**：
- obs-top（obs `From :` 在首字段）：直投 → Postfix smtpd 改写为 X-Mailbox-Line（From 消失 fC=0、dkim=permerror、OpenDMARC 无章）；**经 OpenSMTPD 中继 → 中继插入 Received 使 obs From 不再是首字段 → Postfix 走 cleanup 规范化 → From 保留 fC=1、`dmarc=fail`（策略恢复被咨询）**。单跳性质「首字段 obs From 消失」被任何加头中继破坏——Forward Pass L1 框架（单跳性质在转发下失效）的第一个实验室实例。
- **性质保持表（直投 vs 经 OpenSMTPD）**：U-label 策略空洞（none/none）、群组 rspamd 静默（fail/静默）、domain-literal 空洞（none/none）、重复 From 透传（fC=2/2）、**外域伪造 AR 存活跨中继保持（ar=T/T，OpenSMTPD 不剥）**、obs-colon 签名存活（dkim=pass/pass）、bit8 头区终结（中断行前字段保留、后续沉正文，两路径一致）。即：**攻击者可依赖的空洞类性质对中继是稳健的，而「修复类」行为（X-Mailbox-Line/规范化）对头部位置敏感**。
- 对照：ctl/ctl-signed 基线两路径一致（fail/pass）。

**事故与修复（如实记录）**：
1. 提速轮加的 `address=/lab.test/10.88.0.43` 通配符使搜索域形式（exim.lab.test）解析到 auth-postfix——「exim」列此前实为直投（回执 Postfix 格式是线索）。已删通配符（保留 local=/lab.test/ 权威）。教训：**通配 address= 会劫持容器名搜索域解析**。
2. exim 列阻塞：入口 `exim -bdf -C /etc/exim/exim.conf` 的投递子进程以非 root 传 -C 丢权限（"exim user lost privilege"），队列滞留。正确修法：改用 Debian update-exim4.conf 生成默认路径配置、免 -C。列为待办。
3. 脚本 bug 两处已修：探针 case-id 未按路径参数化（首跑全空）；facts 读取文件名前缀不匹配（离线重算修复，facts.json）；bit8 用 BODY 回退抓取补齐。

### 2026-10-03 四线冲刺结果（xssprobe/、keyprobe/、align2/、dmarcfuzz/）

**A 头内容注入渲染（xssprobe/，5 载荷 × 2 webmail × 列表+详情）——干净阴性**：2047 编码词/原生 img onerror/引号逃逸在 SnappyMail 2.38.2 与 Roundcube 1.6.19 全部正确转义（payload 以纯文本出现，无事件属性、无注入节点；唯一带 onerror 的 img 是 Roundcube 自家 contactpic 占位）。

**B 吊销密钥假 pass（keyprobe/）——规范违规分裂（披露级）**：密钥记录 `p=; p=<真钥>`（重复 tag，首 p= 空=吊销语义，RFC 6376 §3.2 要求拒绝）：**dkimpy fail / perl pass / go pass / rspamd R_DKIM_ALLOW**——三家取末 p= 并验签通过。p= 空（真吊销）与无 p= 则五家全 fail（吊销语义正常执行）。攻击性有限（需受害域区出现此记录），定级披露候选 #3。

**C 真不对齐矩阵（align2/，bank.test 独立二级域 p=reject × 7 种 d=）——无绕过**：对照 pass ✓；d=lab/evil 不对齐 fail ✓；**重复 d=（首 bank 末 evil）：OpenDKIM 取末 d= 验签+AR 报告一致（evil）→ 正确 fail**——AR 报告与密钥取用无分裂，无对齐绕过；首 evil 末 bank 的 pass 需真持有 bank 私钥（非攻击）。尾点 d=：dkim pass + dmarc fail（假拒绝，独立域确认）。大写 d=：对齐大小写不敏感 pass。h5 的子域 caveat 已修。

**D DMARC 记录解析器模糊（dmarcfuzz/，15 畸形记录）——无崩溃、语义模式确认**：OpenDMARC C 解析器在溢出 pct/负 pct/超长/重复 tag/畸形 rua 下全部存活（milter 无中断，canary 正常）。语义：**重复 p= 取末位生效**（`p=none;p=reject`→reject，`p=reject;p=none`→none）——与 d= 取末、密钥 p= 取末合并为**「OpenDMARC/多数实现的末位 tag 优先」跨层模式**（第三次出现）。无 v / v 大小写错 → 规范正确地 none。十六进制 pct 被接受。

**工具链坑（记录）**：dnsmasq 多串 txt-record 串数上限——18 串记录使后续行报 bad option（移除即恢复）；长记录以 ≤3×220 串发布。dnsmasq 单容器语法二分法（throwaway 容器 + --test）是快速定位手段。

**本轮诚实判定：仍无新型漏洞**。新增：1 个规范违规分裂（B）、1 个跨层模式（末位优先）、2 个强阴性（A 渲染转义、C 对齐无绕过）、1 个解析器鲁棒性确认（D）。

### 2026-10-03 冲刺新型漏洞：三个未碰过的攻击面（xssprobe/、keyprobe/、align2/）

用户判定正确：至今无新型漏洞（全部为已知家族新实例/产品缺陷级）。本轮三个全新面：
- **A 头内容注入渲染**：From display-name / Subject 中的原生 HTML 与 RFC 2047 编码词载荷（`<script>`/`<img onerror>`/引号逃逸）在 SnappyMail 2.38.2 与 Roundcube 1.6.19 的列表+详情视图能否存活为可执行节点——命中即存储型 XSS（CVE 级）。
- **B 吊销密钥假 pass**：密钥记录畸形（p= 空=吊销、无 p=、重复 p= 吊销在前/实在后、v= 缺失/错误、k= 不匹配）× 五验证器——吊销语义（RFC 6376 §3.6.1）是否有人不执行。攻击形态：受害域吊销被泄露的旧选择符后，旧签名邮件是否仍 pass。
- **C 真不对齐矩阵**：独立二级受害域 `bank.test`（p=reject，自有 org domain），From=bank.test × d∈{bank.test 对照/lab.test/evil.test/尾点/大写/重复 d= 首为 bank.test}——修掉 lab.test 子域对齐 caveat，对齐绕过空间首次正确打开。**重复 d= 首为受害域**是重点：OpenDKIM 取末 d= 查密钥（c4 证据），但 AR 写的是哪个 d=、OpenDMARC 对齐读哪个 d=——若两者读不同 d= 即无密钥对齐绕过。

### 2026-10-03 组合爆炸结果（hdrfuzz4 1008 全叉积 / 回复绑定 / hdrfuzz5 签名轴 144）

**hdrfuzz4（1008/1008 组合，四分片 780s）**：From(7)×AR(6)×ReplyTo(6)×Sender(4) 穷举全覆盖，补上 h3 随机采样未覆盖的 425 个组合。AR 存活规律完美复现（own 0/168，foreign 4×168/168）；家族分布与 h3 一致（normal 552 / od-void 288 / rsp-void 144 / nostamp 24），**无家族外新组合**。
- **交互效应（新因果数据点）**：obs-ascii From 的 OpenDMARC 盖章行为被「是否有 AR 头在 From 之上」切换——无 AR 时 obs From 是首字段 → Postfix smtpd 改写为 X-Mailbox-Line（From 消失，od=absent 24/24）；有 AR（任意形态，含伪造外域）在上方时 → cleanup 规范化路径，From 保留 → od=fail（24/24）。**攻击者放一个头即可切换网关修复路径**——头序依赖修复的第一个因果证明。
- 事故：shard 0 曾被误启动双进程（同字节重复发送，无数据污染，已杀）；汇总用 sed 分组命令的转义问题导致一次误读，已用 python 重聚。

**回复目标绑定（replyto/）——新发现（MUA 级）**：双 Reply-To 实例（Dovecot ENVELOPE 按物理序返回全部）下，**Roundcube 1.6.19 的 Reply 绑定最后一个实例**：rt1（evil-first）回复 To=受害域 Bank，rt2（victim-first）回复 To=evil Reply——两例均取物理末位。与 DKIM 自底向上选 From 同构的实例选择分歧，落到「用户回复发到哪」这个动作上。SnappyMail 回复窗口自动化仍打不开（与 w1 一致，标记受阻）。攻击形态：钓鱼信带两条 Reply-To，先展示的（部分客户端取首）与 Roundcube 实际回复的（末位）不同。

**hdrfuzz5 签名轴（144 组合：From 6 × d= 6 × h= 2 × 变异 2，三片 90s）**：
- **篡改检测 72/72 全 fail**：签名后改写 From 为攻击者，所有 d=/h= 组合 dkim=fail——无绕过，防线完整（防御侧强阴性）。
- **oversign 防御与 OpenDKIM 不兼容（36/36 fail）**：包含 RFC 6376 §3.5 空字段的 oversign 签名（防头注入的推荐防御，Chen 2020 §7）在 OpenDKIM milter 上全部验签失败——与 w1 的 dkimpy 行为一致，「防御本身破坏已部署验证器」在 milter 层确认。
- 尾点 d=：dkim=pass + dmarc=fail（c2 自分裂在 12 个 From 形态上复现）；重复 d=：OpenDKIM 取末 d= 验签 pass、对齐按 evil.test 判 fail（c4 复现）；FWS/大写 d=：验签 pass + 按组织域对齐 pass。
- **对齐设计 caveat（重要）**：victim 域 xn--mnchen-3ya.lab.test 是 lab.test 子域，`.test` 不在 PSL → relaxed 对齐下与 lab.test 同组织域——矩阵中 pass 均为规范正确行为（非漏洞）。真不对齐需要 evil.test 级别域（org domain 不同）。后续对齐实验必须换独立二级域。
- 工具 bug 修复两处：折叠 AR 提取（续行不并入导致 dkim 判定丢失，已改从存档展开重提取）；sign_custom 对 obs From 的结构校验（obs 形态改用其他形态替代）。

**环境事故与保活**：WSL/Docker Desktop 反复休眠（AGENTS.md 已警告的 resource-saver），导致 hdrfuzz5 前两轮全废（容器集体退出，smtp/verifier 全失败）。已起 **Windows 侧常驻保活任务**（每 15s docker exec，后台任务 exec_c1499e76）——长实验期间勿停，实验全部结束后应停掉。第三轮在保活下正常完成。

### 2026-10-03 目标升级：组合爆炸阶段（hdrfuzz4/5 + 回复目标绑定）

用户指令：更多例=更多**组合**。三线开工：
1. **hdrfuzz4**：hdrfuzz3 四轴（From 池 7 × AR 形态 6 × Reply-To 6 × Sender 4）**穷举全叉积 1008 组合**——随机采样 → 完整目录，任何组合不再靠运气。3-4 分片并行。
2. **回复目标绑定探针**（上轮待办）：双 Reply-To 实例（evil→victim / victim→evil 两种顺序，From 干净）× Roundcube/SnappyMail 的 Reply 动作取哪个实例——ENVELOPE 已证返回全部实例，选择权在客户端。w1 只测过单 Reply-To。
3. **hdrfuzz5 签名轴**：现有 fuzz 全部无签名！新轴 = d= 形态（受害域/外域/尾点/大写/FWS/重复）× From 形态（同池）× 签名在场（真签名+篡改 From 的对齐矩阵）——DKIM/DMARC 对齐空间第一次进 fuzz。

### 2026-10-03 AR 存活矩阵 → SnappyMail 徽章伪造端到端（arsurv/）——新机制候选确认

**六形态存活矩阵**：外域 authserv-id（`receiver.example`）的伪造 AR **存活到邮箱**（b1 正常形态、b3 全小写、b5 折叠均存活）；本域 id 无论大小写都被剥（b2/b6，剥离大小写不敏感）；无 authserv-id 的 b4 存档无 AR（待查细节）。即 **OpenDMARC 1.4.2 的 AR 剥离只针对声称自己 authserv-id 的行**——外域 id 一律放行（对非边界组件是 RFC 8601 行为，但它是默认部署里唯一的 DMARC milter）。

**端到端**：b1（无签名 U/A-label 欺骗 + `Authentication-Results: receiver.example; dkim=pass header.d=<受害域>`）投递后，SnappyMail 2.38.2 详情视图 DOM 节点 `I[fontastic iconcolor-green] dkim=pass (2048-bit key) header.d=xn--mnchen-3ya.lab.test header.b=AAAA ✔`——**绿色徽章内容=伪造 AR 原文**，无任何 authserv-id 信任校验；同邮件 OpenDMARC 盖的是 `dmarc=fail (p=reject)`，From 显示为受害品牌。截图 `arsurv/snappymail-b1-detail.png`。
- 攻击成本：一行头。前置：无密钥、无域注册。
- 与 w1 红叉观察对照：SnappyMail 徽章完全由（可注入的）AR 文本驱动。
- 先例定位：伪造 AR 在钓鱼中存在（Wang S&P 2018 实测）、「MUA 不应显示不可信 AR」是 RFC 8601 反模式警告——**本发现的增量在组合层面**：OpenDMARC 剥离策略（仅本域 id）+ SnappyMail 无校验渲染，在默认开源自建栈上的可复现端到端；产品缺陷级（SnappyMail 侧为主），披露候选 #2（与群组空洞并列）。
- 待补：Roundcube 对照（w1 记录不显示认证状态）；b4 无 AR 细节；多 AR 行时 SnappyMail 取哪一行。

### 2026-10-03 提速 + hdrfuzz2 240 例 + 签名轴（hdrfuzz2/、sigprobe/）

**提速**（10.9s→0.44s/封，25×）：关 rspamd asn/surbl/rbl（黑洞模块仅延迟无判定）+ 补 lab.test/IDN 域 MX+A + `local=/lab.test/` 消 AAAA REFUSED 重试风暴。注意：HFILTER_FROMHOST_NORES_A_OR_MX(1.5) 评分随 MX 发布消失——分歧签名不依赖总分，不受影响，已如实记录。

**hdrfuzz2（3×80 例，~283s）**：多实例 From × 新形态族（路由地址、空地址、冒号后折叠、域内注释、dotless）。240 例中 133 例分歧、29 个唯一结果元组，机制级聚类全部落入六个已知家族：
- M1 From 不可提取→无盖章（59）；M2 OpenDMARC EAI 空洞（25）；M3 literal 空洞（15）；M4 dotless/其他空洞（31）；M5 rspamd 群组静默（58）；M6 双评估器一致正常（52）。
- 广度收获：**M5 群组空洞跨 UPPER/dotless/plain 域名变体全部成立**（OpenDMARC 全部正确咨询——含 obs 路由地址也正确取最终域，关闭 Chen 的 route 悬案）；dotless 顶部实例可为整封信挡掉策略（首实例家族扩展）。
- 工具修正：ENVELOPE 分类器把群组名标记 (NIL NIL display NIL) 误判为 nil，已修（seed21 的 env 标签有此噪声，22/23 干净）。known-outcomes.json 固化 29 元组供后续自动加载。

**签名轴探针（sigprobe/，11 形态 × 固定签名后改写 From）**：修复 rewrite_from 丢 CRLF 的 bug（首跑全 fail 的根因——To 被粘进 From）。结果：**十一种形态中只有 obs-colon（`From :`）签名存活**——perl/go 认出 obs 字段、relaxed 规范化字节与原件完全一致→pass；dkimpy/rspamd 文件扫描不识别→fail；**rspamd milter 路径因 Postfix 先规范化回 `From:`→R_DKIM_ALLOW（同一产品两路径自相矛盾）**。其余十种（群组/dotless/大写值/bare/引号/路由/折叠/空地址）四家全灭——「改写已签名 From」强韧性结论，obs-colon 是唯一裂口（已知家族）。

**结论**：240 例 + 11 签名轴后，开源栈 From 层的行为空间在机制级收敛到六个家族，未发现家族外新机制。工具与方法论资产（已知表 + 高速管线）就位，下一轮应把文法扩到 From 之外（Resent-*、AR 头形态、DKIM tag 全轴）或把 oracle 扩到下游消费（Sieve 不可用、报告消费端待装）。

### 2026-10-02 hdrfuzz 首跑（hdrfuzz/ 目录，seed=7，30 例 + 消融臂）

- 管线端到端跑通：文法生成（display × addr-form × domain × obs × case × extra 六轴）→ 链 oracle（SMTP/AR/rspamd 符号/投递/ENVELOPE）→ 分歧签名 → 已知类去重 → 消融。30 例 581s（~19s/例，rspamd 残余黑洞 DNS 延迟待关 surbl/rbl 提速）。
- **17/30 例安全相关分歧，已知类去重后 0 新类**——符合预期（当日手工类刚编入种子表），验证 oracle+去重管线正确。
- **消融臂**：byte+文件 oracle，180 见/176 有效/4 分裂/4 状态类，零策略级分歧。方法结论有了数字：**oracle 集的贡献大于生成器**（57% vs 2.3% 命中率，且等级不同）。
- RCA 修正：016 的空洞来自 **obs 冒号在顶部**，非引号本地部。
- **新观察（位置依赖的修复分歧）**：obs `From :` 在**顶部**被 Postfix smtpd 改写为 `X-Mailbox-Line: From : ...`（归因：`grep -rl X-Mailbox-Line` 命中 /usr/lib/postfix/sbin/smtpd 与 qmqpd）→ From 对下游全部消失（OpenDKIM permerror、OpenDMARC 不盖章、ENVELOPE From=NIL），邮件照常投递；**中间位置**则被 cleanup 规范化为 `From:`（identity 系列）。同一字节变化、两种身份结局，位置是隐藏变量。
- 待办：文法扩轴（重复 From 对、签名件 d=/h= 形态、obs×form 交叉）、提速（关 surbl/rbl）、多 seed、对 0 新类问题引入「机制级」而非「类级」去重。

### 2026-10-02 战役 V：策略空洞触发面目录（void/ 目录）

**定义**：一组 ASCII 干净、语法可辩护的 From 形态，若使 DMARC 评估器输出 none（策略从未被咨询）而 MUA/ENVELOPE 仍渲染可信发件人，则记为一个「策略空洞触发器」。已知触发器：U-label（CVE-2026-100891）。本战役测试 Chen A6-A8 未覆盖的形态：

- v1 单成员群组：`From: Bank Security: security@<受害域>;`
- v2 空群组：`From: Bank Security:;`
- v3 domain-literal：`From: Bank Security <security@[203.0.113.7]>`
- v4 域后注释（CFWS）：`<security@<受害域> (Bank)>`
- v5 折叠 addr-spec（合法对照）
- v6 仅 obs `From :`（无现代 From，看链上规范化）
- v7 引号本地部（对照）
- v8 双成员群组跨域（9989「多域」情形）
- vc ASCII 对照（已知 fail 路径）

观测：SMTP 回复、存档 AR（OpenDMARC）、rspamd 符号、DNS 查询区、ENVELOPE、浏览器显示（后续）。判据：OpenDMARC `dmarc=none` + rspamd 仍给出策略判定 = 新的评估器分裂型触发器；两者皆 none = 通用空洞（比 U-label 更宽的形态面）。

### 2026-10-02 ar 系列：OpenDMARC 信任输入面三探针（ar/ 目录）——全部阴性/卫生确认

- **ar1 伪造 AR**：无签名欺骗 + 伪造 `Authentication-Results: mail.lab.test; dkim=pass header.d=<受害域>` → OpenDMARC 判 `dmarc=fail (p=reject)`，**伪造的 AR 行在投递途中被剥离**（存档无此行）。OpenDMARC 1.4.2 不消费伪造 AR；民间 2020 年的绕过在维护版已闭合。
- **ar2 元字符 d=（Chen A4 回归审计）**：d=`victim.test(.attacker.test`（qname 挂攻击者密钥、验签 pass 可达）→ **全链 451 tempfail**；二分定位：OpenDKIM-only/OpenDMARC-only/rspamd-only/DKIM+rspamd 全部 250，仅 **DKIM+DMARC 组合 451**——OpenDMARC 解析 OpenDKIM 盖的 AR 里带 `(` 的 header.d 时解析出错返回 tempfail。
- **ar2b 平衡注释**：d=`victim.test(x).attacker.test` 同样 451。**Chen A4 注释对齐技巧在 OpenDMARC 1.4.2 fail-closed**：不产生错误对齐，只产生该信件的 tempfail（攻击者只能拒自己的信，无服务崩溃，后续邮件正常）。
- **ar3 徽章**：伪造 AR 被剥离，SnappyMail 徽章伪造路径在「milter 链会剥伪造 AR」的栈上不成立——记录为阴性。
- 价值：关闭「Chen A4 在开源自建栈是否存活」的悬案（答案是卫生良好/失败闭合）；同时记录「组合依赖的 tempfail」这一小怪癖（单 milter 全过、DKIM+DMARC 组合才触发）。
- bisect 转录归档：ar/ar2-bisect-*.smtp.txt。

### 2026-10-02 任务二：NFD 变体探针（nfd/ 目录，d1-d3）——阴性结果

- d3（NFD：`u`+U+0308 组合分音符，UTF-8 `6d75cc88...`）：OpenDMARC 与 NFC 同样失败（`<name unprintable>` qname ×2 → `dmarc=none`，存档 AR 的 header.from 为 NFD 字节）；**rspamd 3.4 查询 `_dmarc.xn--mnchen-3ya.lab.test` 并给出 DMARC_POLICY_REJECT**——其转换路径对非 NFC 输入做归一化。
- 结论：**NFD 不扩大 CVE-2026-100891 的范围**。rspamd 同时保留 `INVALID_FROM_8BIT(6.0)+FROM_INVALID(2.0)` 启发式（17.4 分，默认阈值会拒）。
- d1/d2 作同批对照：A-label → 两评估器一致 fail/REJECT；NFC → OpenDMARC none、rspamd REJECT（复现）。

### 2026-10-02 任务三：显示层取证（display/ 目录，5 张截图）

- Roundcube 1.6.19：列表里 d2/d3 显示 `Bank Security <security@münchen.lab.test>`（NFC/NFD 渲染不可区分），d1 只显示 "Bank Security"；**详情视图三封全部显示为受害品牌**——d1（A-label）的 mailto 链接被反向转换为 `mailto:security@münchen.lab.test`。
- SnappyMail 2.38.2：列表三封**完全相同**的 `security@münchen.lab.test` Bank Security（A-label 显示时被转为 U-label）；d2 详情 `"Bank Security" <security@münchen.lab.test>` + mailto 同形。
- 结论：**显示层把 A-label/NFC/NFD 三种形态全部归一为受害者的视觉品牌，而策略层只对 ASCII 形态生效**——绑定链的显示端与策略端结构性脱节，截图为证。
- 过程记录：IAB 下 Roundcube/SnappyMail 的按钮 click 多超时，改用表单 submit/evaluate click/直链（`?_task=mail&_mbox=INBOX&_uid=N&_action=show`）绕过；SnappyMail 登录需 `bob@lab.test`（域配置 lab.test.json 映射 msl-dovecot）。

### 2026-10-02 补做一：NOVELTY_CLAIM.md（U-label vs Chen 2020 §4.2）
对照原文（A3 NUL ambiguity）后写定中英文一句话差异 + 八维对照表，落盘 `NOVELTY_CLAIM.md`。要点：Chen 是畸形 ASCII 元字符 + 组件间字符串截断差异 + 攻击者控制区取回内容；本轮是完全合法 EAI 输入 + 规范强制 U→A 转换在维护版评估器中缺失 + 注册体系结构上不可能解析的 qname + 策略/报告的结构性缺席。A1/A2/A4/A5/A7 逐项列出防混淆。

### 2026-10-02 补做二：rua 监控盲区直接证据（rua/ 目录，r1-r4）

配置：OpenDMARC `HistoryFile /var/run/opendmarc/opendmarc.history`（milter 自写）；`_dmarc.xn--mnchen-3ya.lab.test` 加 `rua=mailto:reports@lab.test` + 跨域授权记录 `xn--mnchen-3ya.lab.test._report._dmarc.lab.test TXT v=DMARC1`。

**HistoryFile（OpenDMARC 自己的评估记录，已快照 `history-snapshot.dat`）**：

| case | from | pdomain | policy | rua |
| --- | --- | --- | --- | --- |
| r1 A-label 欺骗 | xn--mnchen-3ya… | xn--mnchen-3ya… | 16 | `mailto:reports@lab.test` |
| **r2 U-label 欺骗** | **münchen…（原始 UTF-8）** | **münchen…** | **14** | **`-`** |
| **r3 U-label+外域签名** | 同上 | 同上 | 14 | `-` |
| r4 A-label 合法 | xn--mnchen-3ya… | xn--mnchen-3ya… | 15 | mailto:reports@lab.test |

- 即：U-label 欺骗事件在评估器自己的记录里就没有可归属的策略域与报告地址，聚合报告按 pdomain→rua 分组（RFC 9989 聚合语义），**受害域的报告永远只含 r1/r4，不含 r2/r3**。
- `reference-aggregate.json` / `reference-aggregate.xn--mnchen-3ya.lab.test.xml`：参考聚合（明确标注：数据全部来自 milter 的 HistoryFile，脚本只做规范规定的分组；`opendmarc-reports` 本体因 Debian bookworm 缺 `Switch.pm`（源码过滤器模块，容器无网）无法运行，全容器检索无此模块——工具侧缺口如实记录，不影响数据级结论）。
- 新想法（记录）：HistoryFile 的 `from` 字段本身以原始 UTF-8 写入——即「评估记录里的身份形态」也是 U-label；若下游有按 from 域聚合的统计管道，同样吃不到 A-label 形态。policy code 14/15/16 的枚举含义未核对源码，按原始值保留。








