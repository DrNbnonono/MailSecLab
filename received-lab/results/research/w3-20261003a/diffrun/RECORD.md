# diffrun 统一差分矩阵（w3-20261003a）

Runner：`research/lib/diffrun.py`（发送-捕获-计数循环，事实一律出自 `tracefacts.facts`，`known.json` 去重）。目标：smtp:{postfix, exim, osmtpd}（每台直投 msl-mailpit，存档即该 MTA 的原始输出）+ parse:python（任务 5 接入）。臂：threshold（N=55）与 capture（N=25）。门槛：postfix `hopcount_limit=50`、exim `received_headers_max=30`、osmtpd ≈100。

## 判决表（threshold N=55；REJECT=554，BOUNCE=250 后未投递，DELIVER=投递且捕获）

| 形态 | Postfix 3.7 | Exim 4.96 | OpenSMTPD 6.8 |
| --- | --- | --- | --- |
| v00-plain | REJECT | BOUNCE | DELIVER（57<100） |
| v01-obs-colon | REJECT | BOUNCE | DELIVER（obs 保留） |
| v02-case | REJECT | BOUNCE | DELIVER |
| v03-nocolon | DELIVER（沉正文） | **DELIVER（沉正文）** | DELIVER（留在头区） |
| v04-8bit-name | DELIVER（终结头区） | DELIVER（55 条留头区） | DELIVER（留头区） |
| v05-cfws-name | DELIVER（留头区） | DELIVER | DELIVER |
| v06-comment-name | DELIVER（留头区） | DELIVER | DELIVER |
| v07-tab-name | REJECT（规范化计入） | BOUNCE（计入） | DELIVER（obs 形态保留） |

## Exim 捕获臂的新数据（本任务核心增量）

- **字节保留与计数是两个独立维度**：Exim 对 obs-colon **保留原始字节**（capture 臂 obs-colon=25, strict=2，与 OpenSMTPD 相同）**但计入** hopcount（threshold 臂退信）；Postfix 对 obs **改写字节**（strict=27）且计入。E3 的「Exim 保留空白但仍计数」在纯捕获路径上字节级确认。
- v07-tab：Exim capture 臂产出 obs-colon 形态（tab 被保留或改写为空格——tracefacts 把两者都归 obs-colon，字节级差异待查）；Postfix 产出 strict=27（tab 被规范化）；OpenSMTPD 保留 obs 形态不计入。
- **v03-nocolon 修正（对 w2 recfuzz2 的更正）**：Exim 在 N=55 **投递**（不计 nocolon）。recfuzz2 曾记「exim 计 nocolon（v03 退信）」——那是捕获仪器按主题抓取漏掉了无主题消息 + mainlog 队列 id 手工映射错误造成的误读。diffrun 的无主题回退扫描（按 X-Case-ID 搜原始字节）两次复现投递成功。**Exim 的计数集合=plain/obs/case/tab，不含 nocolon/8bit/cfws**。
- 沉正文签名：v03/v04 经 postfix/exim 后 6 条真实头（From/To/Date/Subject/Message-ID/X-Case-ID）沉入正文（`body_headerish=6`，N=25 臂可见；N=55 臂因正文前 50 行被 nocolon 行占据而计 0）。OpenSMTPD 的 v03 无冒号行**留在头区**（no-colon=25/55，真实头保留，主题仍在）。

## 仪器记录

- diffrun-targets.json：exim 容器名动态解析研究网 IP（双网容器取 10.88.x）。
- 栈手术（跑完任务 4-6 后按 STATE 回滚）：exim route→msl-mailpit:1025；opensmtpd relay→msl-mailpit:1025；postfix transport_maps capture@→mailpit。
- 修复两处仪器 bug：fetch 按主题取最新（同主题多封时曾取到旧信）；无主题回退扫描（头区终结语料经中继后主题沉没）。
- 计划自带代码的两处 bug 修复：tracefacts 的 8-bit 名 ASCII 骨架子序列判定（Receíved→receved 缺 i）；diffrun 测试首行无前置 CRLF 的计数断言。
- 既有 test_runtime.py 的 5 个失败与本次无关（未触碰）。
