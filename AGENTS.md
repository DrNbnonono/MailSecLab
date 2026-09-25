# MailSecLab

隔离的本地邮件安全实验室。当前研究不是「Received 能不能无限变长」，而是：RFC 5322 对 Trace 数量不设上限，真实 MTA、解析器和 DKIM 验证器各自用不同规则识别同一段字节，这种不一致会不会改变投递或认证结果。

负责人：朝阳（git 作者 YUN GU，GitHub DrNbnonono）。实验在 2026-08 至 2026-09 完成主测量，尚未写作或投稿。不要把实验室阴性写成「某漏洞已不存在」，也不要向公网发信。

## 证据优先级

文字结论互相冲突时，按这个顺序采信：

1. 原始 `.eml` 与节点日志
2. CSV 等结构化结果
3. `received-lab/results/*/RECORD.md`
4. `notes/` 里的综述

`notes/` 在 `.gitignore` 中，只存在于本机：`项目内容整理.md`、`项目内容调研.md`、`项目试验记录.md`。提交进仓库的事实以 `received-lab/results/` 为准。

环境快照：`received-lab/freeze/PF37-manifest.md`、`received-lab/results/phase3/env.json`。

## 环境与操作

Windows + WSL2 + Docker Desktop。命令在 WSL 里执行，工作目录是 `/mnt/e/MailSecLab/received-lab`。

默认拓扑：`mail-client → postfix1 → postfix2 → postfix3 → Mailpit`。Mailpit Web UI 只绑 `127.0.0.1:8025`。不出公网。

| 组件 | 本实验室版本 |
| --- | --- |
| Postfix | 3.7.11（PF37）、3.11.6（PF11） |
| Exim | 4.96 |
| OpenSMTPD | 6.8.0p2 |
| Mailpit | v1.31.0 |
| rspamd | 3.4 |
| dkimpy | 1.1.8 |
| 其余验证器 | perl Mail::DKIM、go-msgauth v0.6.8 |

Compose profile：默认三跳 Postfix；`mta3b` 为 Exim / OpenSMTPD；`pf11` 为 Postfix 3.11；`parsers` 为 Node / Go；`frspamd` 为 rspamd。

E、I、J3 会改 `relayhost`。换实验前执行 `docker compose restart postfix1 postfix2 postfix3`，并核对三条路由都恢复。Docker Desktop 的 resource-saver 会停掉 WSL 虚拟机，长实验需要保活。

新语料必须做头区结构自检。折叠生成器若在已有 CRLF 上再 `"\r\n".join()`，会造出双 CRLF，头区提前结束。`--style folded` 还可能在同一 Received 里放两个日期，不能当成严格合规的长 Received。

bookworm 的 `opendkim-testmsg` 对一切输入报语法错误，不能当 DKIM 验证器。

## 已可引用的结果

协议：RFC 5322 的 trace 条数 unlimited；RFC 5321 要求能停环，计数阈值只是 SHOULD，且通常不少于 100。实现阈值是配置，不是协议常数。

数量边界（默认配置）：

- 三跳 Postfix，`hopcount_limit=50`：预置 N≤46 投递（最终 Received=N+4）；N=47 由 postfix3 拒绝并退信；N=48 由 postfix2 拒绝；N≥49 由 postfix1 在 DATA 回 `554 5.4.0 too many hops`。
- 单跳：Postfix N=48 投递、N=49 回 554；Exim 从 N=30 起接受后退信（`received_headers_max` 30）；OpenSMTPD N=99 投递、N=100 回 `500 5.4.6`；Mailpit 到 N=120 仍收。
- F3：把 Postfix 调到 100 或把 Exim 调到 60，边界跟着移动。
- `hopcount_limit=8` 的真实环在第 8 跳终止。空信 DSN 放大见 F4：152 B → 4,853 B（31.9×）。不要和 E5 的 205 B → 约 23.8× 合成一个数。

识别差异：

- `X-Received`、`Received-SPF` 不计入 hopcount。大小写变体 `rEcEiVeD` / `RECEIVED` 计入。
- `Received :`（冒号前空白，RFC 5322 obs-received）×100：Postfix 规范化后计数并 554；Exim 保留空白但仍计数，接受后退信；OpenSMTPD 保留这 100 条空白变体且不计入环路阈值。以 `received-lab/results/e-series/e3raw/E3-OSMTPD-received_sp.eml` 为准。严格解析、Python、Go 计 2 条，Node 计 102 条。
- `Receíved`（U+00ED）在 Postfix 路径上会结束头区，后续字段降成正文。Phase 3 语料 V007：python-email 把 From 放进正文，Go 和 Node 仍当头。
- Phase 2 FC150：约 150KB 的折叠 Received 被截到 101,701 B 后仍投递。
- H：没有诚实中继时，文件扫描里 1 条伪造 `192.0.2.10` 就能成为 rspamd 的 source。经过 postfix1 后，source 回到真实会话地址（H3 为 172.22.0.5）。H 系列关闭了依赖 DNS 的 rspamd 模块，分数变化不能解释成 SPF 被绕过。
- I1：本环境已打补丁的 Postfix 3.7.11 与 Exim 4.96 上，SMTP 走私为阴性（first/smug=1/0）。这与 Debian bookworm Postfix ≥3.7.9 的修复线一致，不能外推到未修补版本。

DKIM（密钥 RSA-2048，`d=lab.test`，`s=j1`，relaxed/relaxed）：

- J1：`h=` 覆盖约 150KB 的 `X-Gen`。中继前 154,562 B 为 pass，三跳后 103,283 B 为 FAIL，SMTP 仍 250。
- J2：`l=33` 再追加 101 B，dkimpy 前后都 pass。这是 RFC 6376 §3.7 的前缀语义，不是新的协议漏洞。`l=` 只管正文长度，不管头区。
- J3：签名后插入 `Receíved`，dkimpy 拒解析；过 Postfix 后签名沉入正文。
- K 的最终矩阵以 `received-lab/results/k-series/RECORD.md` 和 `k1_matrix.csv` 为准。KB1 四家都接受。KB2（签名后注入异常头）：dkimpy 拒解析，perl 与 go-msgauth pass，rspamd `R_DKIM_ALLOW`（分数 4.3，动作 greylist）。KB3（重复 From）：dkimpy FAIL，rspamd `R_DKIM_REJECT`，perl 与 go pass。`l=` 追加时 go-msgauth 报 insecure body length tag，另外三家接受。反转 From 后再签名只能说明分裂可重复，还不能单独证明「perl/go 取第一实例、dkimpy/rspamd 取最后实例」。

## 不要写成定论

- F1「rspamd 丢掉 9MB 头」已撤回。原因是语料双 CRLF，头区早就结束。纠正后的真折叠头块上，rspamd 约 56 ms、分数 3.4、无动作。
- G 系列「OpenSMTPD 改写 `Received :` 但不计数」与 E3 原始邮件冲突。OpenSMTPD 是保留空白、不计数。
- G4 的 9,096,191 B 三跳头块：`RECORD.md` 与 `r3_redo.csv` 相反，且没有对应的最终 stored `.eml`。重跑并保存输入、SMTP 回复、三跳日志和结构自检之前，不要引用这个字节数。
- I2 不能证明「完全自洽的伪造链仍然失败」。consistent 语料写死 `172.22.0.3`，真实客户端是 `172.22.0.11`，只接上了主机名。伪造地址还用了不属于 RFC 5737 的 `192.0.113.x`。
- 没有测过 Gmail、Exchange 等托管服务，也没有真实互联网测量。
- 未做 OpenSMTPD 同构多跳或有限环，不能说空白变体能让真实环路一直转。
- 未向 Postfix、Exim、OpenSMTPD、rspamd、dkimpy 披露。K 的验证器差分和 J3 淹没不要直接写成漏洞。

## 文献与教程

阅读顺序和与实验的对应关系见 `references/README.md`。本地 PDF 包括 Sanchez 2010（`CEAS-2010-sdp.pdf`）、Van Staden 2010、Chen 2020、Shen 2021、Liu 2023、Luo 2025、Wang 2025、Andarzian 2025，以及 RFC 5321 / 5322。近五年顶会还没有做系统检索，不要写「无人研究过」。

`tutorials/` 是这 8 篇论文的本地讲解页，交互脚本在 `tutorials/assets/play.js`。页面在 `tutorials/<slug>/`。用仓库根目录的普通静态服务时，地址是 `/tutorials/<slug>/`；`python tutorials/dev_server.py` 会把 `/<slug>/` 也指到同一目录。演示里的 IP 和哈希是教学示例，论文数字以页面正文和 PDF 为准。

## 后续开发

优先补证据，而不是再扫更大的 N：

1. 重跑 G4，留下输入 `.eml`、SMTP 回复、三跳日志、最终 stored `.eml` 和结构自检。
2. 重做 I2：发送前读取真实客户端 IP，伪造地址只用 RFC 5737，并逐项核对主机名、IP、协议和时间是否衔接。
3. OpenSMTPD 同构双跳和有限环，检验空白变体是否只是让旧式字段多活。
4. DKIM 重复字段：只签一次，再分别改第一处或最后一处，对照 RFC 6376 §5.4.2。
5. 未修补的 Exim 4.92 只作为 I1 的阳性对照，不要在已修补版本上继续穷举走私载荷。

改实验脚本时，比较的是同一字节流在不同组件上的解释。定位邮件用 `X-Case-ID`；头区可能被终结时，改为在整封 raw 里搜索。
