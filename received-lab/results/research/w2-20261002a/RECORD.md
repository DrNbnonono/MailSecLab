# w2-20261002a 四路线实验记录

运行日期：2026-10-02。前置：w1-20261001a 的认证链（msl-auth-postfix → OpenDKIM 2.11.0 无 libunbound → OpenDMARC 1.4.2 → Dovecot 2.3.19 LMTP）。签名密钥复用 w1 的 RSA-2048（lab.test selector `cal`）。过程现象与新想法按时间序在 `LAB_JOURNAL.md`。本文件只放固化结论与证据位置。

> **2026-10-02 定位修正**：U-label 绕过核心已被 **CVE-2026-100891**（Weitong Li，2026-09-28，VulDB）覆盖——本 run 为独立复现。与该 CVE 的关系、独有增量（rua 报告空洞、NFD 阴性结果、服务端消费面、显示层截图）见 **`UPSTREAM.md`**；Chen 2020 对照见 `NOVELTY_CLAIM.md`（已加状态横幅）。

## 栈变更（相对 w1 收尾状态，重跑前先看）

1. auth-postfix：`smtpd_milters` 增加 `inet:msl-rspamd:11332`（末位）。
2. rspamd：spf 模块启用；dmarc 模块启用（`no_reporting=true`）；`local_networks = "127.0.0.0/8"`；`actions reject=999; add_header=6`。
3. msl-dns（RUN_ID 仍为 w1-20261001a）：extra-dns.conf 新增 `xn--mnchen-3ya.lab.test`（SPF -all、DMARC p=reject、`cal._domainkey` 发布 w1 公钥）与 `cal._domainkey.evil.test`（同一公钥）。
4. OpenDMARC `RejectFailures` 已复原为 false；其 resolv.conf 已复原为 Docker 内嵌 DNS（临时指向过 10.88.0.11 转发器取 qname 字节证据）。
5. msl-dns 容器时钟比宿主慢约 25 分钟（14:18 重启后），DNS 日志归属用 qname 模式匹配，勿用 `docker logs --since`。

## A 线：EAI 身份绑定（eai/、eai-enforce/、qname/fwd.log）

核心机制：**OpenDMARC 1.4.2 不做 U-label→A-label 转换（RFC 9989 §5.3.1 / RFC 8616），对原始 UTF-8 From 域的 `_dmarc` 查询直接携带 UTF-8 字节，NXDOMAIN 后按「无策略」处理**；rspamd 3.4 同一场景转换为 A-label 查询并取到 p=reject。

证据链（victim = `münchen.lab.test` / A-label `xn--mnchen-3ya.lab.test`，发布 p=reject）：

1. **qname 字节**（`qname/fwd.log`，DNS 转发器抓线）：OpenDMARC（10.88.0.42）查询 `_dmarc.` + label `6d c3 bc 6e 63 68 65 6e`（`münchen` 原始 UTF-8），重试一次；A-label 对照组查询 `xn--mnchen-3ya` 正常。rspamd（10.88.0.30）对 U-label From 查询 `_dmarc.xn--mnchen-3ya.lab.test`。
2. **决策翻转**（`eai-enforce/`，OpenDMARC RejectFailures=true 期间）：同一欺骗信 A-label 形态 `550 5.7.1 rejected by DMARC policy`；U-label 形态 `250` 投递进箱，AR `dmarc=none (p=none)`。合法签名对照 `dmarc=pass (p=reject)`。实验后配置已复原。
3. **评估器分裂**（`exec/`，z13-z16 全投递双判定）：z14/z15（U-label 欺骗）OpenDMARC AR `dmarc=none` vs rspamd `DMARC_POLICY_REJECT`，同一 qid；z13/z16 两评估器一致。
4. **假阴性/监控盲区**：合法 IDN 邮件（From U-label、DKIM 以 A-label 正确签名且 pass）同样 `dmarc=none`——对齐判定从未发生。**rua 报告空洞的直接证据**（`rua/`，r1-r4）：OpenDMARC HistoryFile（milter 自写，快照 `history-snapshot.dat`）里 U-label 欺骗事件的 `from`/`pdomain` 为原始 UTF-8、`policy 14`、**`rua -`**，而 A-label 事件正常落 `rua mailto:reports@lab.test`；按 pdomain→rua 的聚合语义，受害域 `xn--mnchen-3ya.lab.test` 的报告只含 r1/r4、永远不含 r2/r3（`reference-aggregate.json`、`reference-aggregate.xn--mnchen-3ya.lab.test.xml`，标注为对 milter 自身记录的参考聚合——`opendmarc-reports` 因镜像缺 Switch.pm 无法运行，见 LAB_JOURNAL）。
5. **诚实边界**：rspamd 的 `INVALID_FROM_8BIT(6.0)+FROM_INVALID(2.0)` 对 8-bit From 加分（默认阈值下 z10/z11 被 554 拒）——启发式针对「8-bit 字节」而非身份绑定；OpenDMARC-only 栈（Postfix+OpenDKIM+OpenDMARC）无此层。探针早期 header-To≠envelope-RCPT 的 FORGED_RECIPIENTS 伪影 z13 起已修正。
6. 附带现象：Postfix 3.7 在未声明 SMTPUTF8/BODY 时接受 8-bit 头值；Dovecot ENVELOPE 以 IMAP literal 原样返回 UTF-8 From（`{17}münchen.lab.test`）；RFC 2047 编码词不解码原样返回。

**8-bit 字段名头区终结（A-3，eai/eai-a0-utf8-fieldname.*）**：`X-Ünknow: one` 插在 DKIM-Signature 之后 → 文件级 dkimpy=parse-error / perl=pass / go=pass / rspamd=pass；Postfix 收 250 并投递，cleanup 在无效字段名处静默终结头区（不插空行），From/To/Date/Subject/X-Case-ID 全部沉入正文（存档字节可证）；OpenDKIM `dkim=permerror`；OpenDMARC 不盖章；Dovecot HEADER.FIELDS 找不到 X-Case-ID、ENVELOPE 全 NIL。

## B 线：服务端/执行型消费面（exec/、nfd/、display/）

1. **Dovecot ENVELOPE 对重复 From 返回全部实例列表**（物理顺序）→ 瘦客户端取首元素=顶部实例。实例绑定全景：DKIM/OpenDKIM=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部（w1）、SnappyMail=顶部（w1）。`exec/imap-probe.json`。
2. **SEARCH HEADER FROM 为 any-instance 语义**：过滤/归档可被未验证实例触发。
3. **A-label 字符串搜不到 U-label 邮件**（`SEARCH HEADER FROM "xn--mnchen-3ya"` 不命中任何 U-label From 信）：按注册形态搜索/过滤对 U-label 欺骗全盲。
4. 未声明 CHARSET 的 UTF-8 搜索串被 Dovecot 接受（宽松行为）。
5. rua 报告生成器实验未做原生工具运行（见 A 线第 4 条与 UPSTREAM.md）——参考聚合已补。
6. **NFD 变体（nfd/，阴性）**：OpenDMARC 对 NFD 与 NFC 同样失败；rspamd 3.4 对 NFD 归一化成功并给出 `DMARC_POLICY_REJECT`（DNS 查询 `_dmarc.xn--mnchen-3ya.lab.test`）——NFD 不扩大 CVE-2026-100891 范围。
7. **显示层（display/，5 张截图）**：Roundcube 与 SnappyMail 把 A-label/NFC/NFD 三种 From 形态**全部渲染为受害者的 Unicode 品牌**（Roundcube 对 A-label 的 mailto 也反向转换；SnappyMail 列表三封完全相同）——显示层归一化与策略层 ASCII-only 的结构性脱节，端到端可视证据。

## ar 系列：OpenDMARC 信任输入面（ar/，2026-10-02 追加）

全部阴性/卫生确认，价值在关闭悬案：

1. **ar1 伪造 AR 注入**：OpenDMARC 1.4.2 不消费伪造的 `Authentication-Results`（判 dmarc=fail），且伪造行在 milter 链中被剥离（存档无此行）。2020 年民间记载的绕过在维护版闭合。
2. **ar2/ar2b Chen A4 注释对齐回归审计**：d= 带元字符（未闭合/平衡 `(` 均测）、qname 挂攻击者密钥可达验签 pass 的前提下，**OpenDKIM+OpenDMARC 组合对该信返回 451 tempfail**（二分转录 ar2-bisect-*.smtp.txt：单 milter 与 DKIM+rspamd 组合全部 250）。Chen 2020 的 A4 在 OpenDMARC 1.4.2（Debian stable 2026 默认）fail-closed：不产生错误对齐，攻击者只能 tempfail 自己的信。
3. **ar3 SnappyMail 徽章伪造**：依赖伪造 AR 存活投递，本栈被剥离，路径不成立（阴性）。

## 战役 V + hdrfuzz（void/、hdrfuzz/，2026-10-02 追加）

1. **策略空洞触发面（void/，九例）**：群组语法=**rspamd 侧空洞**（OpenDMARC 反而正确提取组员判 fail——与 U-label 方向相反的评估器分裂）；domain-literal=双侧空洞 + **空 `header.from=` 的 AR**；空群组/仅 obs From=双侧空洞 + OpenDMARC 不盖章；双域群组=无任何 AR。对照组（注释/折叠/引号本地部带 display）全部正常。
2. **hdrfuzz v1（research/lib/hdrfuzz.py，hdrfuzz/）**：文法×链 oracle 差分模糊器，参考 REQSMINER（文法+状态）、Inbox Invasion（端到端 oracle）、Andarzian（差分+最小化）。首跑 30 例：17 分裂、0 新类（管线验证）；消融臂证明 oracle 集是主要增益来源。已知类种子表编码当日手工战役结果。
3. **Postfix smtpd 的 X-Mailbox-Line 行为（新观察）**：顶部 obs `From :` 被改写为 `X-Mailbox-Line:`（smtpd/qmqpd 二进制归因），From 字段对下游全部消失而投递照常；中间位置则被规范化为 `From:`。**修复行为的位置依赖**是此前未记录的隐藏变量。

## hdrfuzz2 与签名轴（hdrfuzz2/、sigprobe/，2026-10-03）

1. **管线提速 25×**（rspamd 黑洞模块关闭 + DNS 补全 + local 权威；评分副作用 HFILTER_FROMHOST_NORES 消失已记录）。
2. **240 例文法战役**：29 唯一结果元组、六机制家族收敛（M1 不可提取 59 / M2 EAI 25 / M3 literal 15 / M4 dotless 31 / M5 rspamd 群组静默 58 / M6 正常 52）。**无家族外新机制**。M5 跨域名变体全部成立（披露候选加固）；obs 路由地址两评估器均正确（阴性，关闭 Chen route 悬案）。
3. **签名轴 11 形态**：仅 obs-colon 存活（perl/go pass、dkimpy/rspamd 文件 fail、**rspamd milter ALLOW——产品内自分裂**）；其余全灭（韧性结论）。
4. 资产：`known-outcomes.json`（29 元组）、`research/lib/{hdrfuzz,hdrfuzz2,sig_probe,void_probe,ar_probe,eai_*,nfd_probe,rua_aggregate,dns_fwd,imap_probe}.py` 工具族。

## 组合爆炸轮（hdrfuzz4/、replyto/、hdrfuzz5/，2026-10-03）

1. **hdrfuzz4 全叉积**：1008/1008 组合（From×AR×ReplyTo×Sender），AR 存活规律 100% 复现，无家族外组合。**交互效应**：伪造 AR 在场与否切换 Postfix 对首字段 obs From 的修复路径（X-Mailbox-Line 删除 ↔ cleanup 规范化），OpenDMARC 盖章从 absent 翻到 fail——头序依赖修复的因果证明。
2. **Roundcube Reply 绑定末 Reply-To 实例**（replyto/rtb-*）：双实例时回复目标=物理最后一条（与显示 From 的底部选择同构），evil-first 时回复竟去受害域、victim-first 时去 evil。MUA 实例选择分歧落到回复动作。
3. **hdrfuzz5 签名轴 144 组合**：篡改检测 72/72 fail（防线上无绕过）；**oversign 防御在 OpenDKIM 上 36/36 验签失败**（防御不兼容，与 w1 dkimpy 结论连成一线）；尾点/重复 d= 行为在 12 形态复现。**对齐 caveat**：victim 是 lab.test 子域，relaxed 对齐按组织域全通过——后续对齐实验须用独立二级域。
4. 环境事故：WSL/Docker 反复休眠毁掉两轮 h5；Windows 侧保活任务（exec_c1499e76）运行中，实验结束后停。

## recfuzz2：hopcount 计数分裂矩阵（recfuzz2/，2026-10-03）

**三 MTA × 八形态环路判决矩阵**（N=55 触发 pf/exim 阈值，N=105 触发 osmtpd）：
1. 同一封 55 条 obs Received 信 → Postfix 554 / Exim 退信 / OpenSMTPD 投递（三种判决）。
2. **普适计数盲区族**（CFWS 名/注释名/8-bit 名/tab 名）：留在头区可见、对 ≥2/3 家计数器不可见——**计数器免疫的 trace 伪造**（H 系列取证直接相关）。
3. 跨 MTA 计数分歧：obs（exim 计/osmtpd 不计）、tab（pf+exim 计/osmtpd 不计）。（更正 2026-10-03 w3 diffrun：「无冒号（exim 计）」为误读——exim 在 N=55 投递 v03、不计 nocolon；当时 mainlog 队列 id 映射有误且投递件无主题导致按主题捕获漏抓。exim 计数集合=plain/obs/case/tab，见 w3 `diffrun/RECORD.md`。）
4. 诚实定级：不使真实环不死（AGENTS P6）；后果=trace 伪造免疫+判决不确定性+DSN 放大面。
5. 证据：recfuzz2/matrix.json + facts 系（*.stored.raw 原始捕获）+ exim mainlog 退信行 + N=105 六例 smtp 转录。

## 攻击 3 + Received 差分模糊（utf8env/、recfuzz/，2026-10-03）

1. **SMTPUTF8 信封层**：无参数 U-label 信封被 `501 5.1.7` 拒（声明强制）；带参数时评估层 SPF 落入 no-record 空洞（R_SPF_NA）但投递层被 `5.6.7` 退信（Dovecot LMTP 不声明 SMTPUTF8）——同一标识符的三层命运，CVE 家族信封侧边界。
2. **Received/IMF 差分第一轮（36 例）**：全接受无截断；四种命运跨三 MTA 一致（obs 规范化计数保留/大小写保留/无冒号沉正文/8-bit 名终结头区）——**修复类变换是末跳依赖**（末跳 cleanup 最后改写，中继只追加）。下一轮设计：每中继直投原始捕获以隔离各自行为。
3. exim 正确镜像 `received-lab-exim:v3`（配置就位默认路径+免 -C+端口 25）产出，修复矩阵三列齐。

## 攻击 1：异构 MTA 修复矩阵（repair/，2026-10-03）

**L1 框架（Forward Pass「单跳性质在转发下失效」）的第一个受控实验**：11 探针 × 直投/OpenSMTPD 中继（exim 列阻塞于 -C 配置信任，待办）。
1. **核心机制**：顶部 obs From 的 X-Mailbox-Line 改写依赖「首字段」位置；中继插入 Received 即破坏该前提 → Postfix 改走规范化 → OpenDMARC 从无章变为 fail。**头部位置=跨组件不被跟踪的状态**。
2. **空洞类性质对中继稳健**：U-label/群组/字面量/重复 From/外域 AR 存活/obs 签名存活全部透传保持——攻击者可跨中继依赖。
3. 环境修正：删除 `address=/lab.test/` 通配（劫持容器名解析，曾使 exim 列实为直投）；exim 待办=update-exim4.conf 免 -C。证据：repair/facts.json（离线重算）、matrix.json、rp-*.stored.eml 22 份。
4. 文献锚：LITERATURE_LEADS.md L1；对照 Chen 2020 图 6c（Fastmail 黑盒观测，本实验为受控复现+机制归因）。

### parsedmarc 离线装包受阻（工具缺口）

容器无网，parsedmarc 及其依赖无法离线安装（同 opendmarc-reports 缺 Switch.pm 先例）。报告消费端验证未做，不影响数据级结论；如需复测，先准备离线 wheel 目录再挂载。

## 四线冲刺（xssprobe/、keyprobe/、align2/、dmarcfuzz/，2026-10-03 深夜）

1. **XSS 渲染**：5 载荷 × 2 webmail × 列表+详情全转义——干净阴性（w1 以来显示层首查）。
2. **吊销密钥**：`p=; p=真钥` → dkimpy fail / perl+go+rspamd pass（取末 p=，违反 RFC 6376 §3.2 重复 tag 必须拒绝）——披露候选 #3；真吊销（p= 空）与无 p= 五家全 fail。
3. **真不对齐（bank.test 独立域）**：重复 d= 的 AR 报告与密钥取用一致（都末位）→ **对齐层无绕过**；尾点 d= 假拒绝确认。
4. **DMARC 记录解析器**：15 畸形记录无崩溃；重复 p= 取末位生效——「末位 tag 优先」第三次出现（d=/密钥 p=/策略 p=），跨层模式记录。
5. 工具链：dnsmasq 多串 TXT 上限（≤3×220 串）；canary 校验纳入 D 线脚本。

## AR 存活 + hdrfuzz3 千例（arsurv/、hdrfuzz3/，2026-10-03）

1. **AR 存活规律**：OpenDMARC 1.4.2 剥离规则=仅删本域 authserv-id 的 AR；外域 id 全存活（630/630，含伪造 `dmarc=pass (p=reject)` 与 obs 形态；本域 0/157）。**SnappyMail 2.38.2 将存活的外域伪造 AR 渲染为绿色 DKIM-pass 徽章**（DOM 实证 + 截图 `arsurv/snappymail-b1-detail.png`）——一行头的显示层信任指示器伪造，披露候选 #2。
2. **hdrfuzz3：900 例**（3×300 并行，8 分钟）——AR/Reply-To/Sender 轴首扫。**domain-literal 为双评估器空洞**（rspamd 静默 139 例 + OpenDMARC none），群组空洞 117 例复现。双 Reply-To 时 ENVELOPE 返回全部实例（回复绑定交客户端，待办）。
3. Resent-From/Sender 不构成显示替代（两 webmail 列表+详情均绑 From，干净阴性；Chen A8 边界确认）。obs 路由地址两评估器均正确（阴性）。
4. parsedmarc 安装被离线阻塞确认（PyPI 不可达）。

## 新机制猎取的开放脉（2026-10-02 检索结论）

- **DMARC rua 报告投毒**：伪造聚合报告 XML 邮寄到受害域 rua 地址（无认证、人人可发）、消费端解析/统计被污染——**未发现专门学术研究**（检索 2026-10-02）。阻塞项：需真实消费端（parsedmarc 等）做产品级验证，离线环境装包受限。
- **IMAP BODYSTRUCTURE 服务端解析 vs 瘦客户端**：未发现正式研究（最近邻 Inbox Invasion CCS'24 做的是检测器 vs 客户端；PortSwigger「Splitting the email atom」是实践侧先例）。风险：与 CCS'24 影子重叠。

## C 线：d=/s=→qname 构造（qname/，c1-c4）

1. **c2 尾点**：OpenDKIM `dkim=pass header.d=lab.test.`（DNS 视为同一区）+ OpenDMARC `dmarc=fail`（字符串比较不对齐）——**同一链内 pass/fail 自分裂**，方向为合法信假阴性。文件级 dkimpy=tool-error / 其余 pass。
2. **c4 重复 d= tag**：OpenDKIM 取最后一个 d= 并以该域出 AR（`header.d=evil.test`，dkim=pass），dkimpy 按 RFC 6376 §3.2 拒绝（fail），perl/go/rspamd pass——**密钥层身份绑定由验证器的 tag 选取顺序定义**。
3. **c3 d= 内 FWS**：四家全不一致（fail / parse-error / pass / none）；链上 OpenDKIM 剥 FWS 后 pass。
4. c1 大写 d=/s= 全 pass；AR 保留 `header.d=LAB.TEST` 原始大小写。
5. 待补：c2/c3/c4 的逐家 qname 字节归属（用 dns_fwd.py 转发器对逐家重跑）。

## D 线：组合审计积累

本轮新增可引用的组合事实：上述 A/B/C 全部发生在维护版默认可部署配置的单条链内（Postfix 3.7 + OpenDKIM 2.11 + OpenDMARC 1.4.2 + rspamd 3.4 + Dovecot 2.3.19）。w1 已有的 Roundcube/SnappyMail 显示分裂与本轮 ENVELOPE 结果合并成实例绑定矩阵。RFC 9989（2026-05）§5.3.1/§11.5 为规范锚点。

## 与先例的差异声明（写作前必读）

**精确差异声明见 `NOVELTY_CLAIM.md`**（中英文一句话版本 + 八维对照表 + 相邻机制防混淆清单）。

- Chen 2020 §4.2/§4.3/§5.1 覆盖：ASCII 元字符域（NUL/括号）的 AR 注入与查询分歧、SPF 策略查询分歧、空白包围 From、转发规范化制造识别差异（Fastmail）、多 From、替代身份头。**本轮 U-label/U→A 归一化分歧不在其列**——输入合法性（合法 EAI vs 畸形 ASCII）、分歧来源（规范强制转换缺失 vs 低层截断差异）、攻击原语（结构性缺席 vs 攻击者控制内容）三处均不同。检索（2026-10-01/02）未发现 EAI 身份绑定的四大级先例（最近邻为 UASG 2019 白皮书与 RFC 6530/6857/9989 规范文本）。
- 投稿主张的边界：OpenDMARC-only 栈的 p=reject 绕过 + rua 报告空洞是主机制；rspamd 内容启发式在默认阈值的拦截是必须如实报告的缓解因素；未测真实互联网与托管服务商。
