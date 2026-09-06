# I 系列实验记录（2026-09-06）

**I1 · SMTP 走私**（RFC 5321 §4.1.1.4 end-of-DATA；CVE-2023-51764 家族）
**I2 · Received 链自洽伪造 vs rspamd 链一致性**（承接 H3）

**环境**：全部复用现有容器（无需新装）：Postfix 3.7.11 / 3.11.6、Exim 4.96、
OpenSMTPD 6.8.0p2、Mailpit v1.31.0、rspamd 3.4。
**工具**：`scripts/probe_ehlo.py`（EHLO 能力探针）、`scripts/send_bdat.py`（BDAT 发送）、
`scripts/send_raw_data.py`（裸字节 DATA 发送）、`scripts/mk_i1_payload.py`（走私 payload）、
`scripts/mk_i2_msg.py`（链自洽伪造语料）。驱动：`run_i_series.sh` / `run_i1_v3.sh` /
`run_i_final.sh` / `run_exim_v2.sh`。

## I0 · 能力与宽容性探针

| MTA | CHUNKING (BDAT) | 直连裸 `LF.LF` DATA 分裂 |
| --- | --- | --- |
| Postfix 3.7.11 | **支持**（250-CHUNKING） | 否 |
| Postfix 3.11.6 | 未广告（作为接收方未测 BDAT） | 否 |
| Exim 4.96 | **支持** | 否 |
| OpenSMTPD 6.8 | **不支持**（BDAT → 500 Invalid command） | 否 |
| Mailpit v1.31 | 不支持 | 否 |

I1b：5 台 MTA 直接接收含裸 `LF.LF` 的 DATA 流 → **全部严格**（单封投递、无分裂）。
结论：本环境所有 MTA 作为**接收端**都不是走私目标。

## I1 · BDAT→DATA 中继走私矩阵

有效中继对（first/smug = 第一封/走私封 是否到达 Mailpit）：

| 中继对 | CRLF.CRLF（对照） | LF.LF（走私尝试） |
| --- | --- | --- |
| postfix1(3.7) → postfix2(3.7) | 1/0 | 1/0 |
| postfix1(3.7) → postfix2n(3.11) | 1/0 | 1/0 |
| exim(4.96) → postfix2(3.7) | 1/0 | 1/0 |
| exim(4.96) → postfix2n(3.11) | 1/0 | 1/0 |
| postfix1 → mailpit（端口修正后） | 1/0 | 1/0 |

无效/受限对：opensmtpd 作为 BDAT 接收方（无 CHUNKING，500）；exim→mailpit 对
（retarget 端口 25 vs mailpit 1025，基础设施问题，非走私结论）。

**结论（阴性）**：在全部 10 个有效中继对上，**未复现 SMTP 走私**——第一封投递、
走私封从未投递。即：本版本组合中，BDAT 接收→DATA 中继的 dot-stuffing 与
end-of-DATA 判定均为安全（Exim 4.96 中继时对裸 `LF.LF` 也做了处理，或 Postfix
接收端严格要求 CRLF.CRLF）。Debian bookworm 的 3.7.11/4.96 打包版本已含针对
CVE-2023-51764 的部分缓解，这与 2023-12 后的 distro 补丁时间线一致。

**方法论教训（本轮事故）**：
1. `sed 's|port = [0-9]*|...|'` 会命中 `transport = to_mailpit` 里的子串
   `port = `（`[0-9]*` 匹配空）→ transport 名被改成 `1025to_mailpit` → exim 拒载。
   **修复：sed 一律锚定行首**（`s|^  port = .*|...|`）。
2. `docker cp` 从 Windows 挂载拷入的文件带 0777/异常属主 → exim 拒载
   （"wrong owner, group, or mode"）。**修复：重建容器（镜像层配置权限正确），
   retarget 只用 `sed -i`（保留 inode 属主/权限）**。
3. `docker exec` 忘加 `-i` → heredoc 进不了容器，"payload 未生成"。
4. Docker Desktop resource-saver 在交互空闲时停 WSL VM（全容器同时 255）；
   实验脚本内嵌 keeper 循环（每 4s `docker info`）保活。

## I2 · 链自洽伪造（对 rspamd）

构造与真实中继头完全衔接的自洽伪造链（末跳 by = client.lab.test (172.22.0.3)，
恰好接上 postfix1 真实头的 from），经 postfix1 中继后扫描：

| 链形态 | derived source IP | 分数 |
| --- | --- | --- |
| plain（无伪造链） | 172.22.0.9（真实） | 1.0 · no action |
| **consistent（自洽伪造链）** | **172.22.0.9（未变）** | 1.0 · no action |
| inconsistent（H0 型断裂链） | 172.22.0.9（未变） | 1.0 · no action |

**结论（阴性）**：经一台诚实中继后，即使伪造链与真实头完全衔接，rspamd 的
source 认定仍由真实会话 Received 决定 —— rspamd 的信任锚定在"最新会话头"
（有真实 SMTP 会话的 MTA 所加的头），而非链行走的字符串一致性。
与 H3（直接文件扫描时伪造链可劫持 source）合并，构成完整图景：
**伪造 source 的必要条件是攻击者控制可见链顶部（无可信中继）**。

## 数据文件

- `i1_matrix.csv`（全矩阵，含失败对与重试）、`i1_exim_retry.csv`
- `i2_chain.csv`、`I2-*.json/.stored.eml`
- 各用例 payload `*.payload`（每条 ~420B，全部保留作为走私测试证据）
