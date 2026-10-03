# CONFIRMED CANDIDATES —— w4 候选的规范符合性判定（A3）与上游查重（A4）

run：`results/research/w5-20261003a/confirm/`（本文件 + conformance.json + normative-index.json + report-groups.json + reduce-report.json）。
输入：w4-20261003a/gramfuzz 150 条 lab_confirmed 候选 → 119 机制族（mech 聚类）→ 38 报告组 → 逐组×组件三值判定。判定为 LLM 辅助人工裁决；每条 RFC 引文由脚本从本地 RFC 文本按行号抽取（行号与编辑器口径一致，可核）。

**净结果：10 条 violation 级 findings（披露池）· 86 条 defensible（论文素材池）· 29 条 unspecified（阴性照记）· 4 条仪器更正（含 2 条 v1 幻影判定的撤销）。**
组件版本按 AGENTS.md 环境表；A4 为只读检索（2026-10-03），未做任何对外联系。

## 0. 方法与折叠逻辑

- **规范条目索引**：normative-index.json 共 **654 条**（RFC 5321×341 / 5322×66 / 2045×7 / 6376×171 / 6532×10 / 8601×39 / 8617×20；关键词独立成词；含行号与节号；实测关键词行数与 grep 口径一致——计划预期的 800–1500 高估了这七份 RFC 的实际密度）。
- **报告折叠**：119 族 → **38 组**，组键 =（op 类 × P 主机制 × 真实改写方集合 × X 判定形态）；osmtpd 拒收与 D 子型为组属性。X 判定形态不同的不并组（任务纪律）。
- **T 判定基准**：以「实际发送的 corpus 文件 vs 各中继存档」的 difflib 行差分重算改写（stage2 的 gen_preserved 以变异前 gen_bytes 为参照，75/236 例变异打进了生成头，产生大量幻影——见 §5 仪器更正）。
- **D 判定**：RFC 3501 不在原七份 RFC 内，从 rfc-editor 只读取回存档于 `E:/Gramfuzz/rfc/rfc3501.txt`（与 setup 期 RFC 下载同性质）。

折叠后按真实改写方分布：postfix 出现在 30/38 个改写组（157/235 例真实改写，其中 133 例obs 冒号规范化）；exim 16 组（38 改写 + 29 例纯 WSP 折行丢弃）；osmtpd 4 组（13 改写：From 域名补全重串行化 3、Return-Path 9、行尾 1）。

## 1. 报告组表（38 组）

| 组 | op 类 | P 主机制 | 真实改写方 | X 形态 | 族数 | 成员 | 系列 | osmtpd 拒收 | D 子型 | 代表最小子/代表例 |
|---|---|---|---|---|---|---|---|---|---|---|
| G01 | obs-colon | py-zone-death | p | none | 23 | 70 | P/T | 0 | other | reduced/gf-sender-guided.tab-colon-0000.eml |
| G02 | damage | go-whole-error | e+p | none | 13 | 27 | P/T | 13 | - | reduced/gf-obs-from-byte.flip-0435.eml |
| G03 | damage | go-whole-error | none | none | 7 | 19 | P/T | 6 | other | reduced/gf-arc-aar-line.del-0100.eml |
| G04 | obs-colon | py-zone-death | e+p | none | 7 | 17 | P/T | 0 | other | reduced/gf-arc-aar-guided.tab-colon-0004.eml |
| G05 | fold | go-whole-error | e+p | none | 9 | 13 | P/T | 9 | - | reduced/gf-from-guided.fold-line-0196.eml |
| G06 | damage | py-zone-death | e+p | none | 4 | 11 | P/T | 0 | - | reduced/gf-authres-byte.flip-0917.eml |
| G07 | fold | go-whole-error | none | none | 4 | 9 | P/T | 4 | - | reduced/gf-arc-aar-guided.fold-line-0040.eml |
| G08 | obs-colon | py-zone-death | p | perl-solo-parse-error | 3 | 7 | P/T/X | 0 | - | reduced/gf-dkim-tags-guided.tab-colon-0006.eml |
| G09 | damage | node-zone-death | p | none | 3 | 5 | P/T | 0 | - | reduced/gf-obs-received-line.del-0067.eml |
| G10 | damage | py-zone-death | e+o+p | none | 2 | 5 | P/T | 0 | - | reduced/gf-sender-byte.flip-0688.eml |
| G11 | damage | py-zone-death | p | none | 5 | 5 | P/T | 0 | - | reduced/gf-obs-from-line.del-0158.eml |
| G12 | obs-colon | py-zone-death | e+o+p | none | 1 | 5 | P/T | 0 | - | reduced/gf-return-path-guided.tab-colon-0005.eml |
| G13 | obs-colon | py-zone-death | e+p | dkimpy-rspamd-fail | 5 | 5 | D/P/T/X | 0 | other,syntax_error | reduced/gf-from-guided.space-colon-0000.eml |
| G14 | damage | go-zone-death | e+p | none | 3 | 4 | P/T | 0 | - | reduced/gf-from-byte.delete-0844.eml |
| G15 | obs-colon | py-zone-death | p | dkimpy-tool-error-drown | 2 | 4 | P/T/X | 0 | other | reduced/gf-obs-from-guided.tab-colon-0018.eml |
| G16 | obs-colon | py-zone-death | p | dkimpy-rspamd-fail | 2 | 3 | D/P/X | 0 | placeholder,syntax_error | reduced/gf-from-guided.tab-colon-0036.eml |
| G17 | damage | go-whole-error | none | dkimpy-rspamd-fail | 2 | 2 | P/T/X | 1 | - | reduced/gf-from-line.del-0106.eml |
| G18 | damage | go-whole-error | none | perl-solo-parse-error | 1 | 2 | P/T/X | 1 | - | reduced/gf-dkim-tags-line.del-0087.eml |
| G19 | damage | py-zone-death | e+p | perl-solo-parse-error | 2 | 2 | P/T/X | 0 | - | reduced/gf-dkim-tags-byte.flip-0029.eml |
| G20 | damage | py-zone-death | none | none | 2 | 2 | P/T | 0 | - | reduced/gf-obs-from-byte.flip-0974.eml |
| G21 | fresh | py-zone-death | p | none | 2 | 2 | P/T | 0 | - | reduced/gf-obs-received-fresh-0000.eml |
| G22 | damage | from-flip-only | p | dkimpy-rspamd-fail | 1 | 1 | P/X | 0 | - | reduced/gf-from-guided.dup-line-0080.eml |
| G23 | damage | go-whole-error | e+p | dkimpy-rspamd-fail | 1 | 1 | P/T/X | 1 | - | reduced/gf-from-byte.flip-0038.eml |
| G24 | damage | none | e+p | none | 1 | 1 | P/T | 0 | - | reduced/gf-received-line.dup-0599.eml |
| G25 | damage | py-zone-death | e+o+p | dkimpy-rspamd-fail | 1 | 1 | D/P/T/X | 0 | placeholder | reduced/gf-from-byte.flip-0004.eml |
| G26 | damage | py-zone-death | e+p | dkimpy-parse-error-drown | 1 | 1 | D/P/T/X | 0 | syntax_error | reduced/gf-obs-from-line.del-0006.eml |
| G27 | damage | py-zone-death | e+p | dkimpy-rspamd-fail | 1 | 1 | D/P/X | 0 | other | reduced/gf-from-byte.flip-0035.eml |
| G28 | damage | py-zone-death | p | dkimpy-parse-error-drown | 1 | 1 | P/T/X | 0 | - | reduced/gf-obs-from-line.del-0081.eml |
| G29 | damage | py-zone-death | p | dkimpy-tool-error-drown | 1 | 1 | P/T/X | 0 | other | reduced/gf-obs-from-line.del-0033.eml |
| G30 | fold | go-whole-error | none | perl-solo-parse-error | 1 | 1 | P/T/X | 1 | - | reduced/gf-dkim-tags-guided.fold-line-0023.eml |
| G31 | fresh | node-zone-death | p | none | 1 | 1 | P | 0 | - | reduced/gf-obs-received-fresh-0005.eml |
| G32 | fresh | py-zone-death | e+p | dkimpy-parse-error-drown | 1 | 1 | D/P/T/X | 0 | placeholder | reduced/gf-obs-from-fresh-0000.eml |
| G33 | fresh | py-zone-death | p | dkimpy-tool-error-drown | 1 | 1 | P/T/X | 0 | other | reduced/gf-obs-from-fresh-0002.eml |
| G34 | obs-colon | py-zone-death | e+p | dkimpy-tool-error-drown | 1 | 1 | P/T/X | 0 | - | reduced/gf-obs-from-guided.tab-colon-0116.eml |
| G35 | obs-colon | py-zone-death | e+p | perl-solo-parse-error | 1 | 1 | P/T/X | 0 | - | reduced/gf-dkim-tags-guided.tab-colon-0001.eml |
| G36 | obs-colon | py-zone-death | o+p | dkimpy-rspamd-fail | 1 | 1 | D/P/T/X | 0 | syntax_error | reduced/gf-from-guided.tab-colon-0008.eml |
| G37 | obs-colon | py-zone-death | o+p | none | 1 | 1 | P/T | 0 | - | reduced/gf-from-guided.tab-colon-0174.eml |
| G38 | obs-colon | py-zone-death | p | dkimpy-parse-error-drown | 1 | 1 | D/P/T/X | 0 | syntax_error | reduced/gf-obs-from-guided.space-colon-0007.eml |

## 2. violation 级 findings（披露池，10 条）

> 每条含：条款引用（RFC 名+行号+原文）、一句话行为、最小子/证据、A4 上游初判。T5（mbox 行歧义）在 w4 四条已知可披露中属 borderline——本轮判 violation（V4），与 dkimpy 崩溃（V1）均计入。

### V1. dkimpy 1.1.8：消息首行为 WSP 折行时 IndexError 崩溃（健壮性）

- **组件**：dkimpy；confidence: **high**；组覆盖 4 组
- **条款**：（无——健壮性底线，崩溃类不依赖条款）
- **行为**：攻击者以一封首行为单个 TAB 的信使 dkim.verify() 消费方崩溃/不可用；同信 perl/go/rspamd 均 pass——同一封信四种命运（T5 链的文件臂半边）
- **证据**：reduced/gf-obs-from-fresh-0002-sign.eml（759B 最小子，首行 `\t\r\n`）容器内复现：dkimpy 1.1.8 dkim/__init__.py:372 `headers[-1][1] += lines[i]+b"\r\n"` → IndexError: list index out of range（非 DKIMException，未被模块级 verify() 捕获）
- **A4 上游**：known=False；fixed_in_latest=False；检索：https://bugs.launchpad.net/dkimpy（11 个 open bug 无一匹配；检索式 IndexError/rfc822_parse/obs/whitespace）；最新版 1.1.8（PyPI）=实验室版本，容器内复现崩溃（checked 2026-10-03）

### V2. dkimpy 1.1.8：对 obs 合法头整信拒解析，有效签名不可验（RFC 5322 §3.1）

- **组件**：dkimpy；confidence: **medium**；组覆盖 4 组
- **条款**：RFC 5322 §3.1（rfc5322.txt L527–534）：「In some of the definitions, there will be non-terminals whose names start with "obs-".  These "obs-" elements refer to tokens defined in the obsolete syntax in section 4.  In all cases, these productions are to be ignored for the purposes of generating legal Internet messages and MUST NOT be used as part of such a message.  However, when interpreting messages, these tokens MUST be honored as part 」
- **条款**：RFC 5322 §4.5.7（rfc5322.txt L2112–2113）：「obs-received    =   "Received" *WSP ":" *received-token CRLF」
- **条款**：RFC 5322 §4.5.8（rfc5322.txt L2115–2117）：「4.5.8.  Obsolete optional fields obs-optional    =   field-name *WSP ":" unstructured CRLF」
- **行为**：obs-received/obs-optional 合法形态（`Received :`、`From\t\t\t:`）使带有效签名的信在 dkimpy 处 parse-error 而 perl/go/rspamd pass；Postfix 规范化后转 fail（T2/KB2 链）——验证分裂的最干净实例（w3 sigprobe2）
- **证据**：reduced/gf-sign-anchor-kb2-sign.eml（KB2 锚最小子，`Received :\r\n` 注入于有效签名之上）：dkimpy=parse-error / perl+go+rspamd=pass；reduced/gf-obs-from-fresh-0000-sign.eml：`From\t\t\t:` → dkimpy MessageFormatError "Unexpected characters in RFC822 header"（obs-optional 合法形态被拒）
- **A4 上游**：known=False；fixed_in_latest=False；检索：https://bugs.launchpad.net/dkimpy（同上，无 obs 解析拒绝相关 bug）；1.1.8 仍拒 obs 合法头（checked 2026-10-03）

### V3a. Postfix 3.7.11：规范化既有 Received 行的 obs 冒号（`Received :`/`Received\t:` → `Received:`）

- **组件**：postfix；confidence: **high**；组覆盖 5 组
- **条款**：RFC 5321 §4.4（rfc5321.txt L3178–3182）：「An Internet mail program MUST NOT change or delete a Received: line that was previously added to the message header section.  SMTP servers MUST prepend Received lines to messages; they MUST NOT change the order of existing lines or insert Received lines in any other location.」
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **行为**：MUST NOT change a Received: line 的直接字面违反——trace 完整性条款；w3 diffrun 已确立（T1），本轮 133 例 obs 冒号规范化中 obs-received 入口 23 例
- **证据**：对照实际输入（corpus/gf-received-guided.tab-colon-0038.eml 首行 `Received\t:;\t\t\t(G…`）：postfix 存档为 `Received:;…`——冒号前 WSP 被删；exim/osmtpd 逐字节保留。另一例 gf-obs-received-fresh-0001：`Received :(` → `Received:(`（exim/osmtpd 保留）
- **证据**：归因 postfix 核心：E 系列在无 milter 的默认三跳栈（received-lab-postfix1，同样 3.7.11）上同样把 `Received :` 规范化后计数（AGENTS.md E3）——非 milter 伪影
- **A4 上游**：known=False；fixed_in_latest=None；检索：postfix.org 无 GitHub tracker；announcements/RELEASE_NOTES/man 页（3.11.6 容器内 grep）无 obs 头规范化记载；3.11.6 未复测（留披露批次），无 changelog 修复迹象（checked 2026-10-03）

### V3b. Postfix 3.7.11：规范化身份/模板头的 obs 冒号（`From\t\t\t:`/`To\t:`/`Date :`/`Subject :`/`Message-ID\t:`/`X-Case-ID :` → 严格形态）

- **组件**：postfix；confidence: **high**；组覆盖 11 组
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **行为**：T1 扩展到全部 13 入口与模板头（w4 RECORD 新 1 的字节级确认+计数修正）；对 h= 覆盖该头的 DKIM 签名是改写性破坏；副作用是把 dkimpy 的 obs 拒解析修复为可解析（sigprobe2 的修复实例）
- **证据**：真实普查：postfix 对模板头同样规范化——`To\t:`/`Date :`/`Subject :`/`Message-ID\t:`/`X-Case-ID :`/`From\t:`（如 gf-received-guided.tab-colon-0010 的 To、gf-obs-received-guided.tab-colon-0230 的 Message-ID）。obs 冒号规范化共 133 例（13 入口全覆盖）
- **证据**：归因 postfix 核心：E 系列在无 milter 的默认三跳栈（received-lab-postfix1，同样 3.7.11）上同样把 `Received :` 规范化后计数（AGENTS.md E3）——非 milter 伪影
- **A4 上游**：known=False；fixed_in_latest=None；检索：同 V3a；E3（默认无 milter 栈）证明非 milter 伪影（checked 2026-10-03）

### V4. Postfix 3.7.11：mbox From_ 形首行抬升为 X-Mailbox-Line 并以空行歼灭头区

- **组件**：postfix；confidence: **high**；组覆盖 11 组
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **行为**：一个字节类别（空格 vs TAB）翻转 Postfix 整个处理路径：DKIM-Signature 与全部身份头沉入正文→过 postfix 后 perl/go/rspamd=none、dkimpy=fail、Dovecot ENVELOPE 占位（w4 RECORD 新 1 全链）。上游为 Qualys/Mythos 安全缓解的有意设计，副作用未报告
- **证据**：输入 diff 复核（corpus/gf-obs-from-fresh-0002.eml）：首行 `From \t:"\t  ` → 存档 `X-Mailbox-Line: From \t:"\t  `（更名抬升）；其后 milter 头（AR/X-Spam）后插入空行——头区在此终结，输入其余行（含 DKIM-Signature 与全部身份头）逐字节保留但全部落入正文区。exim/osmtpd 路径无 X-Mailbox-Line、头区完整
- **证据**：postfix master smtpd.c L3782-3791（本地取回 /tmp/smtpd.c）：`if (strncmp(start + strspn(start, ">"), "From ", 5) == 0) { out_record(out_stream, REC_TYPE_CONT, "X-Mailbox-Line: ", 16); }`——带注释 `Qualys+Mythos: DOS in mbox line reading loop`（安全缓解为有意设计）；3.7.11 与 3.11.6 二进制均含该串（容器内核验）
- **A4 上游**：known=True；fixed_in_latest=False；检索：机制为有意安全缓解：master smtpd.c L3782-3791 注释 Qualys+Mythos（mbox 行读循环 DoS 修复）；3.7.11 与 3.11.6 二进制均含；但头区歼灭副作用无任何 announcement/man 页记载——副作用大概率未报告（checked 2026-10-03）

### V6. Exim 4.96：丢弃头部纯 WSP 折行（obs-FWS 合法字节）

- **组件**：exim；confidence: **high**；组覆盖 13 组
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **条款**：RFC 5322 §4.2（rfc5322.txt L1809–1817）：「4.2.  Obsolete Folding White Space In the obsolete syntax, any amount of folding white space MAY be inserted where the obs-FWS rule is allowed.  This creates the possibility of having two consecutive "folds" in a line, and therefore the possibility that a line which makes up a folded header field could be composed entirely of white space. obs-FWS         =   1*WSP *(CRLF 1*WSP)」
- **行为**：obs-FWS 合法的折行字节被静默删除（w4 RECORD 新 3；真实计数 29 例，从 23 修正）；对 h= 覆盖该头的 DKIM 签名是改写性破坏；与 postfix/osmtpd 的逐字节保留形成中继差分
- **证据**：输入 diff 复核（corpus/gf-received-guided.tab-colon-0010.eml）：exim 存档删除输入的纯 WSP 折行 `' '`（difflib delete op）；同类 29 例（RECORD 新 3 的 T6，真实计数从 23 修正为 29）。被删行是 obs-FWS 合法字节（RFC 5322 §4.2）
- **A4 上游**：known=False；fixed_in_latest=None；检索：Exim master ChangeLog（~9000 行，至 4.99.1）无 WSP 折行丢弃/头改写条目（检索式 whitespace/folding/header rewrite/Received）；bugs.exim.org 已退役、code.exim.org 检索接口不可达（记仪器缺口）；4.99.1 无修复迹象（checked 2026-10-03）

### V8. OpenSMTPD 6.8.0p2：From/To/Cc 头经域名补全重串行化——自身主机名注入 + 0x20→0xA0 字节劣化

- **组件**：osmtpd；confidence: **high**；组覆盖 3 组
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **行为**：中继把 listener 主机名注入消息头值并引入破坏折行的非法首字节；w4 RECORD 四条新原语之外的第五条机制（上游源码定位 header_domain_append_callback，任意端口生效）
- **证据**：w4 relay/osmtpd/gf-from-guided.tab-colon-{0008,0174}.stored.raw：From 头值中 `()` → `(@opensmtpd.lab.test)`（把自身主机名注入消息内容）；0174 另有 ` \t` → `\xa0\t`（0x20 变 0xA0，破坏折行首 WSP）；postfix/exim 逐字节保留
- **证据**：OpenSMTPD master smtp_session.c（本地取回）：L2633 对 To/Cc/From 的 RFC5322_HEADER_END 调 `header_domain_append_callback`（L458+，向无域地址追加 listener hostname）——From/To/Cc 头整体经此重串行化；机制为有意设计（提交场景域名补全），对任意端口生效
- **A4 上游**：known=True；fixed_in_latest=False；检索：机制为有意设计：OpenSMTPD master smtp_session.c header_domain_append_callback（L458+，L2633 调用）——From/To/Cc 域名补全重串行化；仍在 master。垃圾触发的自身主机名注入+0xA0 劣化副作用未见报告（openbsd/src 镜像无 issue tracker）（checked 2026-10-03）

### V9. OpenSMTPD 6.8.0p2：基于畸形 trace 头格式 550 拒收（RFC 5321 §3.7.2）

- **组件**：osmtpd；confidence: **medium**；组覆盖 4 组
- **条款**：RFC 5321 §3.7.2（rfc5321.txt L1582–1587）：「environments may not conform exactly to this specification.  However, the most important use of Received: lines is for debugging mail faults, and this debugging can be severely hampered by well-meaning gateways that try to "fix" a Received: line.  As another consequence of trace header fields arising in non-SMTP environments, receiving systems MUST NOT reject mail based on the format of a trace he」
- **行为**：11/73 例拒收由 received/obs-received 入口触发——「receiving systems MUST NOT reject mail based on the format of a trace header field」；confidence: medium 因条款位于网关一节，语境外推到普通接收方
- **证据**：w4 relay/osmtpd/*.smtp.txt：73/236 例 `550 5.7.1 … not RFC 2822 compliant`；按入口 received=7/obs-received=4/from=6/obs-from=7/sender=5/reply-to=7/return-path=3/resent-from=4/authres=5/dkim-tags=5/arc-aar=6/arc-ams=7/arc-as=7——11 例 trace 头触发。master smtp_session.c L2850-2853 TX_ERROR_MALFORMED → 550（有意设计，仍在 master）
- **A4 上游**：known=True；fixed_in_latest=False；检索：有意设计：master smtp_session.c L2850-2853 TX_ERROR_MALFORMED → 550 "not RFC 2822 compliant"，仍在 master；OpenBSD 官方 bug 走 bugs.openbsd.org/邮件列表（无 GitHub issue），检索受限（checked 2026-10-03）

### V10. python email：obs 冒号行终结头区，其下全部头沉入正文（RFC 5322 §3.1）

- **组件**：python；confidence: **high**；组覆盖 15 组
- **条款**：RFC 5322 §3.1（rfc5322.txt L527–534）：「In some of the definitions, there will be non-terminals whose names start with "obs-".  These "obs-" elements refer to tokens defined in the obsolete syntax in section 4.  In all cases, these productions are to be ignored for the purposes of generating legal Internet messages and MUST NOT be used as part of such a message.  However, when interpreting messages, these tokens MUST be honored as part 」
- **条款**：RFC 5322 §4.5.8（rfc5322.txt L2115–2117）：「4.5.8.  Obsolete optional fields obs-optional    =   field-name *WSP ":" unstructured CRLF」
- **条款**：RFC 5322 §4.5.7（rfc5322.txt L2112–2113）：「obs-received    =   "Received" *WSP ":" *received-token CRLF」
- **行为**：obs 合法头之下的 From/Subject/DKIM-Signature 对 python 消费者不可见——P4 一般化到 13 入口（w3 diffrun→w4）；legacy 与 default 两 policy 同形；CPython #93176 仍 open
- **证据**：reduced/gf-sender-guided.tab-colon-0000.eml（271B 最小子）本地复验：`X-Case-ID\t: …` 行之上 From/To/Date/Subject/Message-ID 保留为头，该行起全部沉入 payload；legacy 与 default 两种 policy 同形（CPython 3.13.12）
- **A4 上游**：known=True；fixed_in_latest=False；检索：CPython #93176（gh-93158）“Support obsolete email syntax, fieldnames that are followed by whitespace”仍 open；关联 #76787/#158157（whitespace-padded 头名注入保护绕过，open）；3.13.12 实测行为仍在（checked 2026-10-03）

### V11. msl-auth-postfix 栈：milter 头以空行收尾插入在折行头中间，提前歼灭头区

- **组件**：postfix；confidence: **medium**；组覆盖 5 组
- **条款**：RFC 5321 §3.6.3（rfc5321.txt L1524–1529）：「As discussed in Section 6.4, a relay SMTP has no need to inspect or act upon the header section or body of the message data and MUST NOT do so except to add its own "Received:" header field (Section 4.4) and, optionally, to attempt to detect looping in the mail system (see Section 6.3).  Of course, this prohibition also applies to any modifications of these header fields or text (see also Section 」
- **行为**：`X-Spam: Yes`+空行插入在攻击者折行 Received 头中间——头区提前终结，后续折行续行沉入正文；组件归属（postfix cleanup vs libmilter vs rspamd milter）未从字节面分离，判给整栈并降 confidence
- **证据**：输入 diff 复核（corpus/gf-received-byte.insert-1179.eml [postfix]）：`X-Spam: Yes` 与空行两行被插入在输入折行 Received 头的中间（difflib insert op @in[8:8]）——空行提前终结头区，其后折行续行沉入正文
- **A4 上游**：known=False；fixed_in_latest=None；检索：无公开 tracker 条目（postfix 无 GitHub tracker；rspamd GitHub 未逐条检索——组件归属 postfix cleanup vs libmilter vs rspamd milter 未从字节面分离）；记 confidence: medium（checked 2026-10-03）

finding 覆盖（组级）：

| finding | 组件 | 覆盖组 | 条目数 |
|---|---|---|---|
| V1 | dkimpy | 4 (G15,G29,G33,G34) | 4 |
| V2 | dkimpy | 4 (G26,G28,G32,G38) | 4 |
| V3a | postfix | 5 (G01,G02,G04,G11,G21) | 5 |
| V3b | postfix | 11 (G08,G12,G13,G16,G26,G28,G32,G35,G36,G37,G38) | 11 |
| V4 | postfix | 11 (G01,G02,G04,G05,G11,G13,G15,G29,G33,G34,G38) | 11 |
| V6 | exim | 13 (G02,G04,G05,G06,G13,G14,G19,G23,G24,G26,G32,G34…) | 13 |
| V8 | osmtpd | 3 (G25,G36,G37) | 3 |
| V9 | osmtpd | 4 (G02,G03,G05,G07) | 4 |
| V10 | python | 15 (G01,G04,G08,G12,G13,G15,G16,G21,G32,G33,G34,G35…) | 15 |
| V11 | postfix | 5 (G06,G10,G14,G19,G27) | 5 |

**exit 核对：violation 级 10 条 ≥ 10（计划 A3.3 标准）——达标。**

## 3. defensible 池（论文素材账，86 条条目）

按组件：dkimpy 13、exim 9、go 13、osmtpd 12、perl 13、postfix 11、rspamd 8、stack 7。

主要类别（每类代表判定见 conformance.json entries）：

1. **中继行尾修复**（postfix/exim/osmtpd）：对含裸 CR/控制字节的输入做删 CR/拆行——发送方先违反 RFC 5321 §2.3.8（L660–673），接收方修复属 §6.4 承认的争论区间。
2. **Return-Path 终投删除**（三家中继）：删除攻击者 Return-Path 并（osmtpd）加自身——RFC 5321 §4.4 L3235–3238 终投语义；捕获臂把中继变为终投跳是配置语义，纯中继位置下同行为将触 MUST NOT inspect（论文可写的配置敏感性论点）。
3. **OpenSMTPD 非 trace 550 拒收**（62/73 例）：§7.9 经营裁量 vs RFC 5322 §3.1 obs MUST honor 的未定边界——「拒收 vs 改写」的组合缺陷。
4. **dkimpy topmost-only API**：RFC 6376 §6.1 允许任意顺序与限制数量；对简单 API 消费者是真实降级向量（注入畸形 DKIM-Signature → pass 翻 fail）。
5. **dkimpy/rspamd From 实例选择**（2v2 分裂）：§5.4.2「物理最末实例」MUST 只明文约束签名者，验证者义务仅隐含——leaning-violation（与 AGENTS.md 对 K 系列纪律一致，不进披露池）。
6. **Go net/mail 整信报错**：对非法输入严格拒绝；八种 obs 形态全存活（w3）——严格性可辩护。
7. **AR 垃圾 authserv-id 存活**：RFC 8601 §5 的 MUST 只覆盖本域自称实例；w2 B 线（伪造本域 id）才是 §5 相关实例，结论不变。

## 4. unspecified 池（29 条，阴性照记）

按组件：dovecot 14、go 1、node 2、python 12。

1. **Dovecot ENVELOPE 占位/部分解析**（14 条条目，D5）：RFC 3501 §7.4.2 只规定 From 缺失/为空 → NIL，对「存在但不可解析」无规定——`missing_mailbox@missing_domain` 与 `@syntax_error` 是 Dovecot 自有哨兵值（如实判 unspecified，与计划预期一致）。
2. **python 对非法输入的头区终结**（12 条）：随机损伤字节上的解析器行为未规范。
3. **node/go 计数差**（3 条）：头部计数语义未规范。

## 5. 仪器更正（本工序发现，4 条）

### C1. gen_preserved 参照物错误（幻影改写）

stage2 的 gen_preserved 以变异前 gen_bytes 为参照——75/236 例变异打进生成头，导致 107 例幻影「改写」标记与 163 例漏标（原始计数含 milter 插入伪影）。真实普查（corpus 输入 vs 存档 difflib）：postfix 157 例真实改写 / exim 38 改写+29 WSP 行丢弃 / osmtpd 13 改写。v1 判定中的「空值 Received 删除+空行杀区」（V5）与「exim/osmtpd 冒号前插 WSP」（V7）均为幻影，撤销——两例实际逐字节保留。

**影响**：w4 RECORD §2 的 T 保留组合统计（23/18/24/49）不可再引用；T 判定以本文件真实普查为准

### C2. perl/go 验证器记录值是适配器口径伪影

verify_perl.pl 只打印 $sigs[0]（最顶签名）结果；verify_one.py 的 classify_text 先匹配 "invalid signature"。容器内直跑库：Mail::DKIM 与 go-msgauth 在「有效签名+畸形第二 DKIM-Signature 实例」上逐签名行为正确（sig[1]=pass / "Valid signature for lab.test"）。

**影响**：w4 RECORD 新 2「perl 落单（拒解析整信）」的解读更正为适配器伪影；X7/X8 的四验证器分裂在库层面主要是 dkimpy 简单 API 的文档化 topmost-only 设计

### C3. 签名臂与中继臂测试了不同字节

签名臂注入的是 gen_bytes（变异前），中继臂发送的是 corpus 文件（变异后）——75 例两臂字节不同。

**影响**：X 判定仍然有效（测的是它们测的：纯生成头+有效签名）；跨臂对比（file vs @postfix）对这 75 例应谨慎

### C4. byte.insert-0116 的 (None,None,None) 是缺数据不是拒收

该例（裸 LF）被 corpus_check 三目标一致拦截，relay 臂未执行。

**影响**：不得记为「三家拒收」

## 6. 建议 TAXONOMY 编号接续

- V1（dkimpy IndexError）→ 建议 **X9**（验证器健壮性/崩溃类）。
- V2（dkimpy obs 拒解析）→ 并入既有 T2/KB2 家族（sigprobe2 已立案），不新开编号。
- V3a/V3b（Postfix obs 冒号规范化）→ 并入既有 **T1**（w3 已立案），计数与范围修正（133 例、13 入口、模板头）写入 T1 的 w5 增注。
- V4（mbox From_ 行抬升+头区歼灭）→ 建议 **T5** 保留（w4 RECORD 新 1 已编号），本轮补 §3.6.3 条款判定与上游源码定位（smtpd.c L3782–3791，Qualys+Mythos 缓解）。
- V6（Exim WSP 折行丢弃）→ **T6** 保留（w4 RECORD 新 3），计数 23→29 修正。
- V8（OpenSMTPD From/To/Cc 域名补全重串行化+主机名注入）→ 建议 **T7**（新机制，w4 RECORD 四条新原语之外）。
- V9（OpenSMTPD trace 格式 550）→ 建议 **T8**（新：§3.7.2 判定角度，E3/G 系列未做过条款级判定）。
- V10（python email obs 头区终结）→ 并入既有 **P4**（w3 diffrun 已立案），补 §3.1 MUST-honor 条款判定与 CPython #93176 上游关联。
- V11（milter 区中插入空行歼灭头区）→ 建议 **T9**（新：milter 插入位置的独立维度）。
- ~~V5（空值 Received 删除）~~ / ~~V7（冒号前插 WSP）~~：幻影，撤销（见 C1）。

## 7. 与计划/任务书的偏差

1. normative-index 654 条 < 预期 800–1500（七份 RFC 实际关键词密度；实测与 grep 一致）。
2. 报告组 38 个（目标 30–50 内；v1 曾为 52/58，v3 换真实中继维度后收敛）。
3. v1 判定中的 V5/V7 为幻影，已撤销并记入仪器更正——violation 数从 11 修正为 10，仍达 exit 标准。
4. A4 采只读检索初判，未装新版复测（按任务书留给披露批次）；Postfix/Exim 的 fixed_in_latest 记 None（无 changelog 证据，未复测）。
5. 5/52→38 组折叠中 D 子型与 osmtpd 拒收作为组属性而非组键——判定条目按成员族显式列出，无精度损失。
