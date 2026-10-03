# 跨 run 综合：邮件语义差分的三个层级

一句话：邮件的安全语义不是 message bytes 的唯一函数，而是 message × implementation 的函数。四类语义角色（transport / parser / verifier / security & display consumer）对同一字节各持一套 trace 与身份解释。

层级映射：L1=P、L2=T+X、L3=X+D——攻击原语逐条见 `TAXONOMY.md`（24 条，含 w4 语法 campaign 新增 T5/T6/X7/X8/D5）。

## L1 识别差分（同一字节里有哪些字段、边界在哪）

- Postfix：obs-colon 规范化（含中继出口改写，w3 diffrun 字节级证明）并计数；tab 名规范化并计数；8-bit 字段名终结头区（后续字段沉正文）；CFWS/注释名保留不计；无冒号行沉正文不计。
- Exim：obs-colon **字节保留**但计数（w3 diffrun 纯捕获路径确认——保留与计数是独立维度）；tab 计数；8-bit 名保留在头区不计；无冒号沉正文不计（w3 更正 recfuzz2 误读）。
- OpenSMTPD：obs-colon/8-bit/tab/CFWS/注释名全部**保留在头区且不计入环路阈值**；无冒号行保留在头区。
- parser 三家（w3 diffrun parse 列，E3 手工结论自动化）：python email 对 obs/nocolon/8bit/tab 在首条不合规行处终结头区（From 判不在头区）；Go net/mail 八形态头区全存活、只计 strict+case；Node mailparser 把 obs-colon 与 tab 计入。
- 证据：w2 `recfuzz2/matrix.json`、w3 `diffrun/matrix.json`（八形态×三 MTA×两臂+三 parser）、E3 raw、V007。

## L2 解释差分（字段集合相同，恢复出的语义不同）

- 实例选择：DKIM/perl/go=底部、OpenDMARC=顶部、ENVELOPE=首元素（群组返回全列表）、Roundcube=底部、SnappyMail=顶部；Roundcube 的 Reply 绑定末 Reply-To 实例（w2 replyto）。
- 身份归一化：OpenDMARC 不做 U→A 转换 vs rspamd 做（w2 A 线，CVE-2026-100891 家族）；信封侧 SPF 同族空洞（w2 utf8env，但该栈投递层 5.6.7 退信封住）。
- DKIM tag 语义：重复 d= 取末位（OpenDKIM AR 报告与密钥取用一致，w2 align2——无对齐绕过）；密钥记录重复 p= 取末位（dkimpy 拒、perl/go/rspamd 过，w2 keyprobe）；DMARC 记录重复 p= 取末位（w2 dmarcfuzz）——「末位 tag 优先」跨三层独立出现。
- source 归因：rspamd get_from_ip() = 顶部 Received 的 from-clause（w1 i2）。
- 修复矩阵：七个单跳性质过异构中继后 persist/break/created（w2 repair）——顶部 obs From 的 X-Mailbox-Line 改写依赖首字段位置，任何加头中继破坏该前提（Forward Pass L1 框架的头部层受控实例）。

## L3 决策差分（安全结论或结果翻转）

- 执行翻转：同一欺骗信 550（A-label）vs 250（U-label）（w2 eai-enforce）。
- 评估器分裂：OpenDMARC none vs rspamd REJECT，同一 qid（w2 exec z14/z15）；群组/domain-literal 使 rspamd DMARC 静默（w2 void+hdrfuzz3 千例）。
- DKIM 判定分裂：perl/go pass vs dkimpy/rspamd fail（w1 causal）；**obs 注入信经不同中继后 dkimpy 结论相反**（osmtpd 保留→parse-error 带进邮箱；postfix 规范化→pass，w3 sigprobe2）；oversign 防御在 OpenDKIM+dkimpy 上全 fail（w1 causal+w2 sigprobe，防御不兼容）。
- 监控空洞：rua 聚合永远不含 U-label 事件（w2 rua HistoryFile `rua -`）。
- 显示层：A-label/NFC/NFD 全渲染为受害者 Unicode 品牌（w2 display）；SnappyMail 把存活的外域伪造 AR 渲染为绿色 DKIM 徽章（w2 arsurv）。
- 环路判决分裂：同一封 55 条 obs Received 的信 Postfix 554 / Exim 退信 / OpenSMTPD 投递（w2 recfuzz2 + w3 diffrun）；CFWS/注释/8-bit 名是「保留可见但三台计数器全盲」的普适盲区族（hopcount 免疫的 trace 伪造）。
- 环路安全（阴性）：obs 变体不让真实环路越过 5.4.6（w1 osmtpd-loop）。

## 阴性结果表（攻击模型边界）

| 阴性 | 证据 |
| --- | --- |
| H：诚实中继恢复 rspamd source | w1 i2 |
| I1：修补版走私阴性 + Exim 4.92 对照 | w1 exim492 |
| NFD 不扩大 CVE-2026-100891（rspamd 归一化成功） | w2 nfd |
| 伪造 AR：本域 id 被剥离（0/157）；AR 注释元字符 fail-closed（451） | w2 arsurv+ar |
| XSS 头注入：两 webmail 全转义 | w2 xssprobe |
| 签名后改写 From：72/72 全 fail（无绕过） | w2 sigprobe |
| obs 形态签名：12/12 格全灭（不可伪造可验签名） | w3 sigprobe2 |
| 真对齐矩阵（bank.test 独立域）：无对齐绕过 | w2 align2 |
| DMARC 记录解析器 15 畸形：无崩溃 | w2 dmarcfuzz |
| SMTPUTF8 信封：无参数 501 拒；评估层空洞但投递层 5.6.7 退信封住 | w2 utf8env |

## 与 CVE-2026-100891 的增量边界

见 w2 `UPSTREAM.md`；本文只引用不重述。核心已披露，本项目的增量=报告空洞/显示层/消费面的系统表征 + 三层级框架 + 阴性地图。

## 已知缺口

- OpenDKIM 2.11.0 公钥检索仪器问题（key not found in DNS），实例绑定矩阵缺该列——不补写其选择方向。
- parsedmarc 离线装包受阻，报告消费端未验证。
- 无真实服务测量；结论限于研究网栈与列出版本。
