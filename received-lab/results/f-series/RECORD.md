# F 系列实验记录（2026-09-05）

**研究问题**：Received 头能否无限制增长 —— E 系列已测绘限制面，F 系列按价值顺序回答遗留问题：
F1 字节通道的下游成本；F2 隐藏通道端到端存留；F3 上限是否只是配置常数；F4 DSN 放大网格。

**环境**：同 E 系列（`results/phase3/env.json`）。新增：rspamd 3.4 容器
（Debian bookworm，镜像 `received-lab-rspamd` a3df2e73e9f6；rbl/surbl/spf/dmarc/
replies/url_redirector/attachments 的 DNS 依赖检查已禁用 —— 离线实验无真实 DNS，
禁用配置烧录在镜像 /etc/rspamd/local.d/）。

**工具**：`run_f_series.sh`（F1/F3/F4 主驱动）、`run_f2_only.sh`（F2 重跑）、
`scripts/gen_f1_corpus.py`（字节通道语料）、`scripts/send_folded_xreceived.py`
（hopcount 盲大头注入）、`scripts/count_received.py`（头区变体计数）。

---

## F1 · 字节通道下游成本（parser ×3 + rspamd）

语料：折叠 X-Received ×N（N=1/5/20/50/100，每头 ~90KB），文件 `f1/`。
另扫描两条对照：E3-OSMTPD-received_sp.eml（WSP 隐藏通道产物）与 V007.eml（ET050 头区终结）。

| 文件 | 字节 | py ms | node ms | go ms | rspamd ms | rspamd 分数/动作 |
| --- | --- | --- | --- | --- | --- | --- |
| F1-XF001 | 91,053 | 185 | 307 | 94 | 586 | 10.4 / add header |
| F1-XF005 | 454,589 | 262 | 342 | 118 | 626 | 10.4 / add header |
| F1-XF020 | 1,817,869 | 306 | 366 | 146 | 861 | 10.4 / add header |
| F1-XF050 | 4,544,449 | 363 | 482 | 261 | 893 | 10.4 / add header |
| F1-XF100 | 9,088,749 | 515 | 511 | 182 | 1,172 | 10.4 / add header |
| E3-OSMTPD-received_sp | 13,402 | 231 | 660 | 142 | 249 | 7.9 / add header |
| V007（对照） | 272 | 197 | 292 | 117 | 100 | 3.4 / no action |

计时含 docker exec ~50–80ms 开销；绝对值小（<1.2s @9MB），**解析成本不构成可用 DoS 面**。

**关键发现（解析器差分的安全面）**：
- rspamd 对 9.09MB 头块报文报 `MISSING_MID/FROM/TO/DATE/SUBJECT + RCVD_COUNT_ZERO('0')`
  —— 它的 parser 把巨型头块整体丢弃，报文里的真实 From/To/Subject/Message-ID 全部"失踪"，
  并因此被抬分到 10.4（add header）。同一字节流 python/node/go 三个 parser 均正常解析（无 error）。
- rspamd 对 WSP 隐藏通道产物报 `BROKEN_HEADERS +8.0`（score 7.9）—— **通道骗过 OpenSMTPD
  的传输计数，但骗不过 rspamd 的解析器**。
- rspamd 对 V007 计 `RCVD_COUNT_ZERO`（与 Postfix 一致地失明于 Receíved 变体）。

原始证据：`f1_downstream.csv`、`logs/rspamd_*.json`。

---

## F2 · 隐藏通道端到端（OSMTPD → PF/Exim → Mailpit）

路由：client → OpenSMTPD（WSP 变体 ×N）→ {postfix1 单跳 | exim} → mailpit。
**前置拓扑复位**（见下方事故记录）。结果（`f2_hidden.csv`，证据 `logs/F2R-*.eml`）：

| 路径 | N | 结果 | 最终存储报文头计数 |
| --- | --- | --- | --- |
| → Postfix | 40 | 投递 | **exact=43, wsp=0, ci=43**（40 条 WSP 被 Postfix 规范化转正 + osmtpd/pf/mailpit 各 1）；Node 计 43 |
| → Postfix | 100 | 250 后退信 | Postfix cleanup 判 `hopcount exceeded`（规范化后 >50）→ OSMTPD 生成 DSN |
| → Exim | 25 | 投递 | **exact=28, wsp=0, ci=28**（Exim 同样规范化转正）；Node 计 28 |
| → Exim | 100 | 250 后退信 | Exim 计入 received_headers_max(30) → `suspected mail loop` DSN |

**结论**：`Received<SP>:` 通道只对 OpenSMTPD 一跳有效；报文一旦经过 Postfix 或 Exim，
走私头被**规范化为真正的 `Received:`**（"转正"），随即落入对方的 loop 防护
（hopcount / received_headers_max）被拒或退信。通道宽度 = 连续无计数 MTA 的跳数。

---

## F3 · 上限的配置敏感性

调参后重测边界（`f3_sensitivity.csv`）：

| 旋钮 | 值 | 新边界 | 默认边界（E 系列） |
| --- | --- | --- | --- |
| Postfix `hopcount_limit` | 100 | N=98 投递（total 100），N=99 → 554 | 48/49 |
| Exim `received_headers_max` | 60 | N=59 投递（61 条），N=60 → 退信 | 29/30 |
| Exim `header_maxsize` | 4MB | 552 点从 1.85MB 移到 ~4.6MB（N=50 folded 触发 552） | 1MB |

**结论**：三台上限全部随配置线性移动 —— 上限是实现/配置常数，**不是协议常数**。
（备注：header_maxsize=4M 测试中 N=40/45 的退信由当时仍生效的 received_headers_max=30
触发，与字节无关；552 内联拒绝的位置移动才是字节旋钮的证据。）

---

## F4 · DSN 放大网格（loop limit=8，X-Received 折叠大报文，hopcount 盲）

`f4_amplify.csv`、日志 `logs/f4_*.log`：

| X-Received 头数 | 原文 B | 每圈尺寸增长 | DSN B | DSN/原文 |
| --- | --- | --- | --- | --- |
| 0 | 152 | 362→983→1604（+~620B/圈） | 4,853 | **31.9×** |
| 1 | 91,036 | +621B/圈 | 4,814 | 0.053 |
| 5 | 454,572 | +621B/圈 | 4,814 | 0.011 |
| 20 | 1,817,854 | +621B/圈 | 4,815 | 0.003 |

**结论**：DSN 的绝对尺寸 ≈ 原文头 + ~3.2KB 封装 + 每圈一条 Received（+621B/圈）；
放大率随原文尺寸从 31.9× 衰减到 ~1。放大的本质是**圈数 × 每圈增量 + 全文复制的 DSN**，
而圈数本身受各 MTA loop 防护（8/30/50/100）约束 —— 与 E1 的数量上限闭环。

---

## 事故记录（实验方法论教训）

1. **21:08 第一轮 F 运行**：F2 的 bash `local tgt=$1 n=$2 c="...$tgt..."` 单行声明导致
   `$tgt` 未绑定崩溃；切片重跑时又漏带 helper 函数；F4 的 `$cycles`/`$cyc` 变量名笔误
   在 **F4 中途崩溃且未执行恢复段** —— postfix1 残留 hopcount_limit=8 + loop 拓扑。
2. **21:10 第二轮**：F2 在脏配置上运行，4 个用例全部被残留的 hopcount=8 弹回
   （日志 `cleanup: message rejected: hopcount exceeded`），结果无效。
3. **修正**：`run_f2_only.sh` 增加**前置拓扑复位**（pre-reset）并在记录中打印复位后的
   实际配置再开始发送；F2 重跑（21:20）结果有效。
   **教训：每组实验开始前复位并打印拓扑，而不是只依赖上一组结束时的恢复。**

## 遗留与下一步

- F1 中 rspamd 把 9MB 头块整体丢弃的行为值得单独刻画（其内部 header 上限是多少？
  是丢弃还是转 body？与 DKIM l= 标签组合的后果）。
- WSP 头被 Postfix/Exim 规范化"转正"的细节：转正发生在 cleanup 的哪个阶段、
  是否落日志、对 DMARC/DKIM l= 的影响。
- E4/F2 的 DSN 都进入了 Mailpit（发件人 alice），DSN 内容含原报文多少字节可进一步量化。
