# H 系列实验记录（2026-09-06）

**问题**：伪造的公网源 Received（RFC 5737: 192.0.2.x / 198.51.100.x / 203.0.113.x）
能否改变 rspamd 认定的 source IP？`trusted_networks`/`local_addrs` 翻转是否影响？

**环境**：rspamd 3.4（Debian bookworm，网络隔离 `network_mode: none` —— 见下方稳定性
事故；DNS 依赖模块 rbl/spf/surbl/dmarc/replies/url_redirector/attachments 已禁用）。
语料：`scripts/gen_h_corpus.py`（伪造 Received 置于 DATA 顶部 = 最终链底部 = 时间序最早的
"源"位置；公网 IP 三池轮转）。驱动：`run_h_final.sh` / `run_h_tail.sh`。

## 可观测性方案（插件尝试均失败，最终用 debug 日志）

自定义 lua 插件（task:get_from_ip() → 符号 H_SOURCE_IP）三种放置方式均被
`rspamd_config_is_module_enabled: lua module h_ip is enabled but has not been configured`
拒绝（3.4 对未在主配置注册的外部 lua 模块一律 disable）。**最终可观测**：
`local.d/logging.inc: level="debug"` 后，`rspamd_task_write_log` 行包含 `ip: <derived IP>`
（`grep 'file: <path>' | grep -oP 'ip: \K[0-9.]+'` 提取）。

## 稳定性事故与定位

rspamd 容器反复 `Exited(255)`（35s～数分钟不等，无 OOM、无日志错误）。定位过程：
全容器同时 255 → Docker Desktop resource-saver 停 WSL VM（间隔性，无法从 CLI 控制，
只能用连续后台脚本规避）；rspamd 自身在 `network_mode: none` 下稳定 3 分钟+ 而默认
网络 35s 必死 → **maps.rspamd.com 在线 map 刷新触发 3.4 崩溃**。最终 compose 固定
`network_mode: none`（rspamc 容器内扫本地文件，无需网络）。

## H1/H2 · source 认定矩阵（文件扫描，无会话头）

| N（伪造公网 Received 数） | config A（默认 local_addrs，含 172.16/12） | config B（strict：移除 172.16/12） |
| --- | --- | --- |
| 0 | UNKNOWN | UNKNOWN |
| 1 | **192.0.2.10** · 5.275 · greylist | **192.0.2.10** · 4.175 · greylist |
| 5 | **192.0.2.10** · 5.175 | **192.0.2.10** · 4.175 |
| 46 | **192.0.2.10** · 5.25 | **192.0.2.10** · 4.25 |
| 100 | **192.0.2.10** · 5.325 | **192.0.2.10** · 4.325 |

（config B 分数一致 -1.1：RDNS_NONE/RCVD_NO_TLS_LAST 不再命中；**source 认定不变**。）

## H3 · 关键对照：直接文件 vs 经一台真实 MTA 中继

| 输入 | rspamd 认定 source | 分数 |
| --- | --- | --- |
| H3-RELAY46 原始语料（46 条伪造，直接文件扫描） | 192.0.2.10 | 5.4 greylist |
| 同报文经 postfix1 中继后的 stored 版本（顶部多了真实会话链） | **172.22.0.5**（真实最后一跳） | 1.9 no action |

9MB 真头块（F1-XF100）：score 3.4 / no action；`ip:` 行未产生（超大报文的日志行
格式/截断，未提取到，标注 UNKNOWN）。

## 结论

1. **文件级/端到端无真实中继时，N=1 的伪造公网 Received 即可完全决定 rspamd 的
   source 认定（192.0.2.10）**——与伪造深度无关（1/5/46/100 相同）。
2. **`local_addrs`/trust 收紧不改变 source 认定**：私网（RFC1918）真实跳永远不会成为
   source 候选，rspamd 一路跳过它们取第一个公网 IP。B 配置只改变了计分符号。
3. **真实防御来自链一致性而非 trust 配置**：报文只要经过一台诚实 MTA（产生真实会话
   Received 且 by/from 链条衔接），rspamd 的链行走即断在伪造边界，source 回落到真实
   最后一跳（172.22.0.5），伪造链整体失效（分数 5.4 → 1.9）。
4. 9MB 真头块对 source 认定与评分无额外影响（3.4 / no action）。

**回答主线问题**：Received 链对 rspamd 的信任不是"逐头可信"，而是"从最新会话头
向下走、断在第一个不一致处"——攻击者能伪造 source 的条件是**控制整个可见链的顶部**
（即没有诚实中继），而不是注入任意深度的旧链。

## 遗留

- 9MB 报文的 `ip:` 日志提取未成功（日志行截断或无 derived IP），可用 h_ip 插件的
  正确注册方式（rspamd.conf 主配置 `.plugins` 段）补做。
- DNS 启用后的 RDNS/HFILTER 判定（本环境无真实 DNS）。
- 经 OpenSMTPD（改写但不计数）中继后的 stored 版本 source 认定（预期同 postfix 路径）。
