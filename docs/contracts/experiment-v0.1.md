# MailTrace 研究契约 0.1

`mailtrace-core` 与 `MailReport 0.1` 保持独立。`mailtrace-lab 0.1.0` 提供新的 `CaseSpec`、`SweepSpec`、`ExperimentManifest` 和 `DiffReport`。生成与字段比较为纯函数；只有 `ExperimentStore` 读写归档。

## 用例与确定性

`CaseSpec` 是版本化 JSON，未知属性拒绝。完整示例见 [received-baseline.json](../../experiments/cases/received-baseline.json)。

| 字段 | 默认 / 规则 |
| --- | --- |
| `schema_version` | `0.1` |
| `name` / `purpose` | 用例名称与研究目的，最多 200 / 1000 字符 |
| `seed` | 0；严格整数，0 至 2³²−1 |
| `base_time` | `2026-10-01T12:00:00Z`，必须含时区 |
| `received_count` | 2；0–10,000 |
| `topology` | `chain` 连续链 / `return` 交替回返 |
| `date_profile` | `valid` / `backwards` / `invalid` / `unknown_timezone` |
| `received_position` | `first` / `last`；相对于额外字段列表 |
| `folding` | `none` / `space` / `tab`；作用于 Received 的 by 和日期前 |
| `newline` | `crlf` / `lf` |
| `pre_colon_space` | false；为 Received 与列表字段冒号前加入 SP，保留非标准语法 |
| `headers` | 有序 `[{name,value},...]`；保留重复与顺序，最多 200 项 |
| `max_line_bytes` / `header_bytes` | null 或精确目标；必须为正整数 |

字段名是无冒号 ASCII token，最多 100 字符；字段值最多 100,000 字符，不接收 CR/LF。Received 由专用参数生成，不能再加入 `headers`。重排与重复身份字段通过列表完成；`date_profile` 只影响 Received，额外 Date 字段由列表明确指定。

直接构造原始字节，不使用 MIME 序列化器。相同已解析参数在相同工具版本下产生相同邮件字节；归档 ID、归档时间和采集标签不进入邮件。数量扫描保持旧跳的队列 ID，不会随数量改变已有跳。

行长是头区最长物理行的字节数，排除 CR/LF；不是字符数，也不含正文行。头区大小使用核心 `source.header_size_bytes`：包含最后一字段的换行，排除空白分隔行。`X-Lab-Line` 设置最长行，`X-Lab-Pad` 设置头区大小；填充可折行以遵守指定行长。尺寸不可满足时返回原因及最小可行大小，不截断其他字段。原始正文固定为合成文本。

`SweepSpec` 只有 `axis` 和 `values`：轴为 `received_count`、`max_line_bytes` 或 `header_bytes`，数值列表包含 1–20 个严格整数。每次覆盖一个轴，其他参数固定，最终值重新通过 CaseSpec 校验。请求目标和实测值同时保存。

## 实验清单

三种 `kind` 明确区分：

| kind | 含义 | 是否产生相邻差分 |
| --- | --- | --- |
| `generated_sample` | 单个生成用例 | 否 |
| `parameter_sweep` | 单变量扫描组 | 否；各样本不代表传输跳 |
| `capture_sequence` | 用户给定顺序的采集快照 | 是，仅比较相邻快照 |

Manifest 包含 `id`（32 位十六进制 UUID）、`schema_version`、`name`、`created_at`、`tool_versions`、可选 `sweep`、可选 `derived_from`、有序 `snapshots` 和 `diffs`。ID 和时间属于归档，不影响合成样本哈希。

Snapshot 包含：

- `id`（`snapshot-001` 等）、1 起始 `position`、`source`（generated/imported）。
- `label`、`capture_point`（submitted/ingress/egress/delivered/unknown），可选 `captured_at`、`mta`、`mta_version`、`config_digest`。
- `capture_gap` 表示与前一个快照之间存在缺口；不自动由时间、文件名或链路猜测。
- 可选已解析 `case` 与 `case_artifact`；原始 `eml`、分析 `report` 产物引用。
- `metrics`：`input_sha256`、`input_bytes`、`header_bytes`、`max_line_bytes`、`candidate_received_count`、`recognized_received_count`、`field_count`。
- `smtp_result`、`mta_log`、`delivery_result` 本轮均为 null，不能将分析结果转换为 MTA 接受或拒绝。

每个产物引用含相对 `path`、完整 `sha256`、`size_bytes`。候选 Received 是物理扫描口径，识别数量是核心语义报告中的 route 长度；例如冒号前空格可能产生不同数量。

采集时间若填写，必须包含时区；未知时留空。它仅描述采集，不影响输入顺序。MTA 名称、版本与配置摘要均为用户提供的标签，不构成修改者证明。

## 差分规则与证据

DiffReport 包含 `before_id`、`after_id`、六类 `summary`、`changes`、`capture_gap`、始终为 null 的 `attribution` 及限定结论。结论仅表示变化发生在两处采集之间。

首先按原始字段字节匹配完全相同的实例，再对标准语法字段按明确词法规则匹配格式变化；以保持顺序的稳定字段为锚点，只在锚点区间匹配唯一同名实例。无名畸形候选不会被当作同一字段。重复实例有多种对应关系时保留全部候选，不强行配对。

格式规则只处理字段名大小写、外层 SP/HTAB、CRLF/LF 和明确的折行。标准展开保留 WSP，仅去除 WSP 前的 CRLF，依据 [RFC 5322 §2.2.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.2.3)。LF 转换单独作为词法格式规则，不能据此宣称邮件合法、地址等价或签名仍有效。内部任意空白不会被合并；obsolete/malformed 字段不参与标准格式匹配。

| kind | 解释 |
| --- | --- |
| `added` / `removed` | 未匹配的新字段 / 消失字段 |
| `value_changed` | 锚点区间内唯一同名候选值改变 |
| `format_changed` | 明确规则下词法内容相同，原始字节不同 |
| `order_changed` | 共同唯一字段相对顺序改变，不指定具体移动者 |
| `ambiguous` | 等价或同名重复实例无法唯一对应 |

新增顶端 Received 仅记一次新增，不把其他索引后移算作重排。摘要新增/删除数量同时包括 ambiguous 重复组的净数量变化；数量变化可以确定，具体新增实例不确定。完全相同的重复组也会展示对应不确定，其值未被声称改写。

每项变化包含 `before` 和 `after` 证据列表。每条 EvidenceRef 带 `snapshot_id + header_id`、`name`、半开字节范围 `[start_byte,end_byte)`、1 起始闭区间行号及该原始切片 SHA-256。只使用 MailReport 原始头区 Base64 的切片，不将展示文本重新编码当作证据。非 UTF-8 展示可能有替换字符，原始 `.eml` 和 Base64 仍保留字节。

Received 的 from/by/protocol/queue_id/recipient/timestamp/timestamp_raw/parse_status 前后变化记录在 `received_changes`。完整解析缺陷仍保存在两侧 MailReport，快照分析可查看现有调查提示。前缀缩短只标记为截断迹象，不确认原因；采集缺口和修改者归因分别处理。

## 归档与重开

默认根目录是**后端或 CLI 启动目录**的 `local-experiments`。从项目根启动时为 `E:\MailTrace\local-experiments`；后端环境变量 `MAILTRACE_EXPERIMENT_DIR` 可指定其他根目录，CLI `--store` 优先于环境变量。

```text
local-experiments/<experiment_id>/
  manifest.json
  manifest.sha256
  cases/snapshot-001.json       # 已解析的生成参数（采集实验没有）
  messages/snapshot-001.eml     # 原始字节，包括正文
  reports/snapshot-001.json     # MailReport 0.1，不含正文
  diffs/diff-001.json           # 仅相邻采集实验
```

先写独立 `.pending-<id>` 目录，所有内容完成后重命名为正式目录；失败不返回成功、不覆盖原实验。失败目录保留供排查，不出现在历史中。正常实验目录加入 Git 忽略；手动删除需先核对路径。

重开、读取证据、下载及复现都会检查清单与所有产物哈希/大小/路径。缺失或损坏明确返回完整性错误，不自动修补。写入与读取的清单上限一致；清单内 JSON 参数可因转义而大于原始邮件，内部上限为原始组额度的八倍，发布前也检查。

这些哈希用于本地完整性核查，不是数字签名；能同时修改清单和哈希的人仍能重写归档。

复现生成实验时先重新生成并对比原哈希，再发布新 ID；采集实验复现沿用已核验原始邮件与采集标签重新计算差分，不代表重新执行传输。历史按每页 50 项返回游标，损坏项目标记异常。ZIP 包含完整产物及清单校验，CSV 包含数值指标与 `transport_result=not_measured`。

## 研究限制

单封非空邮件最多 10 MiB；每次最多 20 个样本/快照，原始邮件累计最多 50 MiB；生成最多 10,000 条 Received。研究 HTTP 请求最多 52 MiB，网页代理超时 120 秒。原单封分析请求上限仍为 12 MiB，超时 45 秒。字段变化及双侧候选各自每页 50 项；完整下载保留全部内容。

网页研究页面明确提示自动保存**原始实验邮件**，包括正文。单封分析继续不保存历史。取消等待会中断页面请求，但不保证撤销已开始的后台归档；请刷新历史核查。RelayLab、LimitProbe、ParserDiff、AuthChain 与复杂 MIME 变异留待后续版本。
