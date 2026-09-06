# G 系列实验记录（2026-09-05 晚）

**目的**：承接 F 系列遗留问题 —— G1 rspamd 头块丢弃阈值；G2 丢弃模式；G3 WSP 规范化归因。
**结果**：G1/G2 过程中发现 F 系列语料生成器存在**双 CRLF bug**，F1 的"rspamd 丢头"解读
被撤回并纠正；G3 归因完成且推翻了 F2 的一部分解释。本记录完整保留纠错过程。

**工具**：`scripts/gen_g_corpus.py`、`scripts/gen_g_variant.py`、`scripts/send_g3.py`、
`scripts/count_received.py`、`run_g_series.sh` / `run_g_refine.sh` / `run_g1_v2.sh` /
`run_g1_v3.sh` / `run_g4_r3_v2.sh`（前两个脚本的中途版本有转义事故，已删除）。

---

## 重大纠错：语料生成器双 CRLF bug（21:48–22:16 期间的部分结果作废）

**bug**：`gen_f1_corpus.py` / `send_folded_xreceived.py` / `gen_g_corpus.py` 的 folded()
首行以 `\r\n` 结尾，而 parts 之间又用 `"\r\n".join()` 连接 → 每个巨型折叠头的首行之后
出现**双 CRLF**，头块在那里合法终结，其余 ~90KB 的 "(AAA…" 折行全部成为**正文**。

**影响面**：
- F1 corpus（F1-XF*.eml）：`hdr_lines=2` —— 9.09MB 报文实际只有 ~100B 头 + 9MB 正文。
- R3 原始结果（9.09MB "头块"过三跳链）：实际是 ~100B 头 + 9.1MB 正文，"头块字节通道"
  机制描述错误（已用修复后语料重做，见 G4/R3-redo）。
- F1 的 "rspamd 丢头（MISSING_*）" 解读：**撤回** —— rspamd 是对的，头块确实在那里终结；
  三个 parser 的 rc=0 / from_present 与 rspamd 完全一致。`MISSING_DATE` 是语料无 Date 头。
- G1 早期 "8KB 即触发丢头" 等结果：同一伪影，作废。
- G2（from-first vs from-last 差分）：同一伪影 —— 差分实为"身份头在（意外）头终结符之前/后"。
- **不受影响**：E2（走 send_received.py --style folded，无此 bug）、F2、F3、F4 的测量值、
  E 系列全部数量上限结果、phase1/2/3 全部结果。

**教训**：生成字节级语料后必须校验结构（头块行数/双 CRLF 检查），并在对照 parser 之间
交叉验证。本轮由"G1 阈值反常地小"追查出根因。

## G1（纠正后）· rspamd 对真折叠头块的行为

修复语料后重新生成 F1 corpus（F1-XF100：105 头行、头块 9,068,338B、单 CRLF、
From/To/Subject/MID 在巨型头之后），rspamd 扫描：

| 文件 | 头块 | rspamd | MISSING* |
| --- | --- | --- | --- |
| F1-XF001（~90KB 头块） | 正确折叠 | 29ms · 3.4 · no action | 仅 MISSING_DATE（语料无 Date） |
| F1-XF020（~1.8MB 头块） | 正确折叠 | 15ms · 3.4 · no action | 仅 MISSING_DATE |
| F1-XF100（9.07MB 头块） | 正确折叠 | 56ms · 3.4 · no action | 仅 MISSING_DATE |

变体隔离（`g1_variants.csv` / `g1_v2.csv` / `g1_matrix.csv`，修复后语料）：
折叠/非折叠、单折行/多折行、行长 100–5000、头名 X-Received/X-Giant/Received、
总头块 350B–9MB —— **未发现任何 rspamd 丢头阈值**。三个 parser + rspamd 在所有
正确折叠语料上一致。

## G2 · 字段位置（在修正语境下的含义）

原 G2 差分（from-first 存活 / from-last 失踪）由双 CRLF 伪影造成，不构成 rspamd 行为
证据。保留价值：它演示了"语料首个意外头终结符之后的字段会被所有合规 parser 判为正文"
—— 与 Phase 3C 的 ET050 机制相同。

## G3 · WSP 变体的规范化归因（关键更正）

单发单头变体直接投给各 MTA，比对 input vs stored（`logs/G3*.input/stored.eml`）：

| 变体 | Postfix | Exim | OpenSMTPD |
| --- | --- | --- | --- |
| `Received<SP>:` | **规范化为 `Received:`** 且计数（hopcount） | **保留原样**（stored wsp=1）但计入 received_headers_max | **规范化**但不计数（E3：100 条 WSP 投递后 stored exact/wsp=2/0） |
| `Received<TAB>:` | 规范化（同上） | —（G3B 只测 PF） | — |
| `Subject<SP>:` | **规范化为 `Subject:`**（对所有头生效） | 保留原样 `Subject :` | — |

**归因更正**：F2 中 "PF/Exim 转正" 的解释有误 —— 三个 MTA 的真实行为：
- **Postfix**：规范化所有 WSP 变体头（cleanup 通用行为）+ 计数；
- **Exim**：只计数，不改写；
- **OpenSMTPD**：不计数（loop 盲），但改写。
F2 中 OSMTPD→PF/EX 路径的"转正"来自第一跳 OpenSMTPD（以及 PF 自己）。

## G4 · 修正后的 R3 字节通道（真折叠头块）

修复后的真折叠 X-Received 头块经三跳 Postfix 链（hopcount=50）：

| N | 报文 | SMTP | 结果 | 存储头块 | real Received |
| --- | --- | --- | --- | --- | --- |
| 50 | 4,534,236 B | 250 | 投递 | **4,548,585 B** | 4 |
| 100 | 9,068,338 B | 250 | 投递 | **9,096,191 B** | 4 |

**结论（修正版）**：真正的头块字节通道成立 —— 9.1MB 纯头块、hopcount 全程失明
（Received 恒为 4），唯一约束是 message_size_limit（~10.24MB）。Postfix 对真折叠头
（单头 90KB < header_size_limit）原样保留。

## 方法论教训（新增）

1. 字节级语料必须做结构自检（头行数、CRLF 规范性），首个对照应是"合规 parser 之间一致"。
2. "某个 parser 表现异常" 先怀疑语料，再怀疑 parser —— 本轮 rspamd 是对的。
3. heredoc/转义连环事故（`\\r\\n` 在多层 shell 中三次变形）浪费大量时间：
   生成器一律 Write 工具直写 + `ast.parse` 语法自检后再运行。
4. 实验开始前 pre-reset + 打印拓扑（F 系列教训）继续有效，本轮 G 系列从头执行。

## 遗留

- rspamd 对真 9MB 头块 3.4 分通过 → "字节通道对 rspamd 无害"（结合 F1 修正），
  Rspamd 信任边界（trusted_networks/source 认定）实验仍是下一块。
- Postfix cleanup 规范化 WSP 的日志痕迹与 DKIM l= 交互未做。
- OpenSMTPD "不计数但改写" 的行为值得对上游确认是否有意为之。
