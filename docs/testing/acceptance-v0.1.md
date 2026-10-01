# MailTrace 首版验收矩阵

这里定义实施时必须通过的行为。当前仓库交付设计资料，没有声称下列产品测试已经通过。

## 稳定规则

| code | 默认等级 | 触发条件 | 必须给出的证据/参数 | 不触发的情况 |
| --- | --- | --- | --- | --- |
| HEADER_PARSER_DISAGREEMENT | warning | 物理候选字段未被 Python 识别，或候选计数与语义计数不一致 | candidate_count、recognized_count、semantic_boundary_byte、涉及 header_ids | 正常头区和正文中的伪字段 |
| DUPLICATE_SINGLETON | warning | 被识别的 From/Date/Subject/Message-ID 各有多个字段实例 | field_name、count、各 header_ids | 一个 From 含多个合法 mailbox；重复 Received |
| RECEIVED_PARTIAL | info | 一条 recognized Received 为 partial/unparsed | header_id、hop_id、缺失/无效项 | 只缺少 optional 的 with/id/for |
| LONG_RECEIVED_CHAIN | warning | recognized_received_count > chain_limit | count、limit | 恰好等于阈值；不是按默认 MTA 限制判断 |
| PRIVATE_IP_EXPOSED | info | 某跳唯一确定的 IP 属于 RFC1918/fc00::/7 | ip、scope、对应 hop_id/header_id | 192.0.2.0/24 等文档地址；地址歧义 |
| TIMESTAMP_REVERSED | warning | 相邻两跳可确定时间，当前减前一跳 < 0 | previous_time、current_time、delay_seconds、两个 hop_ids/header_ids | 缺少时区时不猜测差值 |
| ROUTE_DISCONTINUITY | info | 相邻跳均有可用中继主机，前 by 与后 from 比较键不同 | previous_by、next_from、两个 hop_ids/header_ids | 缺失主机；仅大小写或尾部点不同 |
| POSSIBLE_ROUTING_LOOP | warning | 可证据连接的路径非相邻回返，或重复有向边 | normalized_nodes/edge、所有对应 hop_ids/header_ids | A→B、B→C 的正常共享节点；链路不连续不拼接成循环 |

无认证声明是 unknown，不自动生成风险警告。SPF fail、DKIM mixed 等原始声明在认证区域展示，不等价于工具判定为恶意。首版没有 HELO/PTR mismatch 规则，因为还没有 DNS/PTR 查询证据。

## 输入与证据

| 用例 | 输入 | 验收结果 |
| --- | --- | --- |
| basic | 两条合法 Received，ASCII/编码 Subject | hop-001 对应底层字段；两个时间差为 17 秒 |
| header-only | 无分隔空行的邮件头文本 | 正常分析；has_body_separator=false |
| no-received | 只有 From/To/Subject | route=[]，三个认证概要为 unknown，缺少路由不判恶意 |
| body-boundary | 空行后包含 Received/From/Authentication-Results 文字 | 不进入 headers/route/authentication |
| bytes-vs-text | 同一 UTF-8 文本输入 bytes 与 str | 除 input_kind 外报告一致，摘要/偏移相同 |
| folded | CRLF 或 LF 折叠字段 | raw 保留换行，value 展开，Base64 字节与源输入切片一致 |
| bad-header-name | Receíved 或无冒号行后接 From | 保存物理证据与 Python 缺陷，不复活已降为正文的 From |
| received-space | `Received :` 后接合法字段 | 当前 Python 视图提前终止；候选和 recognized 计数分开，差异警告 |
| repeated-values | 完全相同的重复字段 | 每个字段独立 ID 与偏移，不能因值相同合并 |
| raw-roundtrip | 头区含非 UTF-8 字节 | Base64 解码等于原字节，展示可替换，JSON 可解析 |
| deterministic | 两次分析相同输入/选项 | JSON 数据一致，不含当前时间与随机 ID |
| terminal-controls | Subject 含 ESC 与回车 | 文本报告转义控制符，原始证据未改写 |

## Received 与时间

| 用例 | 验收结果 |
| --- | --- |
| route-order | 按字段顺序反转，不按时间戳排序；两种序号满足契约恒等式 |
| ipv4-ipv6 | 验证方括号 IPv4、IPv6 与 IPv6: 前缀；非法 IP 不当作已提取 IP |
| multiple-ip | 两个不同候选 IP 保留列表，ip=null、scope=ambiguous |
| comment-keyword | 注释/引号包含 from/by/分号，不当作子句边界 |
| missing-clause | from/by/time 缺失仍有一跳并给 partial/unparsed |
| missing-semicolon | 不从任意数字拼出日期，给 RECEIVED_PARTIAL |
| timezone | +0800 与 +0000 的同一绝对时刻比较为零延迟 |
| minus-zero | -0000 转 UTC 且标记 utc_local_offset_unknown，不套用本机时区 |
| no-zone | 保留日期原文，timestamp=null，不参与延迟计算 |
| reversed-time | 保留负 delay，发 TIMESTAMP_REVERSED；不重排 hops |
| partial-total | 任一时间未知时 total_observed_delay_seconds=null |
| private-range | RFC1918/ULA 触发私网提示，文档/loopback/link-local 地址有独立分类 |
| chain-threshold | limit=50：50 条不触发，51 条触发；候选而未识别的字段不计入 |
| continuity | A→B、B.→C 视为相接；A→B、D→C 提示缺口 |
| repeated-host | A→B→C 不提示循环；连续 A→B→A 提示可能回返 |
| repeated-edge | 两条 A→B 保留两份证据，提示可能回返，不证明已发生真实环路 |

## 认证声明

| 用例 | 验收结果 |
| --- | --- |
| no-auth | 三个 summary=unknown、verified=false；签名存在也不产生 DKIM pass |
| multiple-authserv | 保留多个 authserv-id，不偏向最后一条或第一条当作可信结论 |
| quoted-semicolon | reason="a;b" 内部分号不分段 |
| nested-comment | 忽略语法注释中的假方法文本，不把其中 spf=pass 当结果 |
| duplicate-property | 重复 smtp.mailfrom 属性保留列表，不覆盖 |
| dkim-mixed | dkim=pass 与 dkim=fail 各有 assertion，summary=mixed，无自动恶意判定 |
| auth-none | `auth.example; none` 只有头部证据，summary=unknown |
| unknown-method | 保留 method，三个标准 summary 不改变 |
| unsupported-result | 保留原 result 并报告缺陷，不变成 pass |
| received-spf | 与 Authentication-Results 独立记录，不覆盖 SPF summary |
| dkim-tags | 只读取 d/s/a 元数据，verified=false |
| arc | 保留 ARC 三类头部的存在，不宣称链验证完成 |

## 安装、CLI 与 JSON

- 清洁虚拟环境中安装核心包后能 import，无需 FastAPI、Node.js、数据库或网络查询。
- 已安装的 `mailtrace analyze PATH` 与 `analyze(path.read_bytes())` 使用同一核心函数。
- `--json` 的 stdout 只有一个 JSON 文档；stderr 放诊断，正文与路径不进入报告。
- 中文 Subject 正常显示；JSON 中时间/ID/引用遵守契约。
- 缺失文件/权限错误/空文件返回 1；参数错误、非正 chain-limit 返回 2；存在 warning 的完成报告返回 0。
- 大小为 10,485,760 字节可读取；超过一个字节被拒绝，不输出截断分析结果。
- 输入类型错误库抛 TypeError；空输入抛 ValueError。

## 验证运行约定

实施阶段从仓库根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".\packages\mailtrace-core[dev]"
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\basic.eml --json
```

当前仅设计文档，以上安装目标尚不存在。验收通过后再把“设计用例”标为“已验证”，记录实际 Python/Pydantic 版本与命令结果。
