# MailReport 0.1 数据契约

本文件定义首版库、CLI、后续 HTTP API 与前端共享的结构。示例见 [report-v0.1.example.json](report-v0.1.example.json)，对应原始输入见 [basic-example.eml](basic-example.eml)。示例是设计样本，不是已实现分析器的输出。

## 公共入口与稳定性

```python
from mailtrace import AnalysisOptions, MailReport, analyze

report: MailReport = analyze(raw_email)
report = analyze(raw_email, options=AnalysisOptions(chain_limit=50))
json_text = report.model_dump_json(by_alias=True, indent=2)
json_data = report.model_dump(mode="json", by_alias=True)
```

上述代码是拟定的接口。`raw_email` 为 bytes 或 str；`AnalysisOptions.chain_limit` 为正整数，默认 50。关键字 `options` 可省略，不把路径、DNS 客户端或 HTTP 请求传入核心入口。

顶层 `schema_version` 固定为字符串 `"0.1"`。日期输出 ISO 8601，UTC 用 `Z`，其他偏移用 `±HH:MM`。未知值为 null；空集合为 []，不能省略约定的字段。列表保持证据顺序，标识按输入位置生成，重复分析不产生不同 ID。

后续增加可选字段仍使用 0.x 小版本；改变字段含义、类型或删字段升级契约版本。消费者使用 schema_version 区分版本，不根据 CLI 版本猜测结构。

## 顶层

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| schema_version | string | `0.1` |
| source | SourceInfo | 输入与原始头区证据 |
| message | MessageSummary | 邮件概要 |
| headers | HeaderField[] | 物理头区候选字段，按原始顺序 |
| route | MailHop[] | Python 识别的 Received，按声明的传输顺序 |
| route_summary | RouteSummary | 候选、识别、结构化数量及观测延迟 |
| authentication | AuthenticationReport | 多个来源的认证声明与汇总 |
| warnings | Finding[] | 稳定规则结果 |
| defects | ParseDefect[] | 结构/字段解析缺陷 |

## SourceInfo 与证据定位

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| input_kind | `bytes` / `text_utf8` | 输入来自字节还是 UTF-8 编码后的文本 |
| input_sha256 | string | 整个输入的 SHA-256 小写十六进制 |
| input_size_bytes | integer | 整个输入大小 |
| header_sha256 | string | 物理头区字节摘要 |
| header_size_bytes | integer | 第一个空行前的字节数，包含最后一个字段的换行 |
| header_base64 | string | 物理头区字节的 Base64；不包含分隔空行或正文 |
| has_body_separator | boolean | 是否找到头区/正文分隔空行；不等价于存在非空正文 |
| semantic_boundary_byte | integer | Python 实际接纳的头区结束位置；半开区间结束偏移 |

摘要只用于复现和比对，不证明发件者身份。保留整封输入的哈希，不把正文或附件放入报告。即使 Python 提前停止识别字段，header_base64 仍包含全部物理头区，用于核查边界差异。

HeaderField 定义：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| id | string | 按原始顺序 `header-001`、`header-002`…；至少三位，超过 999 不截断 |
| name | string/null | 候选字段名称；非法名称无可用 ASCII 名时为 null |
| raw | string | 原始字段整体的 UTF-8 replacement 展示文本，保留折叠与换行 |
| value | string/null | 去字段名和冒号、展开折叠并去除首尾 WSP 的值；语义解析只使用 recognized=true 的字段 |
| recognized | boolean | 是否对应 Python raw_items 中的字段 |
| syntax | `standard` / `obsolete` / `malformed` | 轻量扫描的形状分类，不是完整 RFC 合规认证 |
| start_byte / end_byte | integer | 相对输入开头的半开区间；包含本字段末尾换行 |
| start_line / end_line | integer | 一基行号，首尾均包含 |

不能生成字段候选的孤立行以 `name=null`、`value=null`、`syntax=malformed` 保存。同一字段的折叠行属于同一个记录。恢复真实字节时对 Base64 解码后的头区按 start/end 切片；不要把 raw 字符串重新编码当成原始证据。

## MessageSummary

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| subject | string/null | 第一条被识别的 Subject 的解码文本 |
| from_addresses / to_addresses / sender_addresses | Mailbox[] | 所有被识别的对应字段中的地址，按原始顺序，不去重 |
| return_paths | string[] | 所有被识别的 Return-Path 展开值，保留 `<>` 语义 |
| message_ids | string[] | 所有被识别的 Message-ID 值；不覆盖重复实例 |
| date | string/null | 第一条被识别的 Date，可确定 UTC 时输出规范时间 |
| date_raw | string/null | 与 date 对应的原始日期值 |
| subject_header_id / date_header_id | string/null | 上述摘要值的证据来源 |

Mailbox：`display_name: string|null`、`address: string`、`header_id: string`。不能提取合法邮箱的值仍保留在 headers 并产生缺陷，不猜测缺失的邮箱域。

Subject/Date 取第一条只为了提供摘要，不代表解析歧义已解决。From、Date、Subject、Message-ID 的多个字段实例触发 DUPLICATE_SINGLETON；同一 From 字段中合法的多个 mailbox 不计作多个 From 字段。

## MailHop 与 RouteSummary

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| id | string | 按传输顺序 `hop-001`… |
| header_id | string | 对应 headers 的 ID |
| received_index | integer | 被识别 Received 的原始顺序，一基，最顶端为 1 |
| route_index | integer | 传输视图顺序，一基，最底端为 1 |
| from / by | Endpoint | 主机/IP 声明；JSON 键使用 from，Python 内部可用 from_endpoint 别名 |
| protocol / queue_id / recipient | string/null | 提取到的协议、队列 ID、收件人 |
| timestamp | string/null | 可确定的 UTC 时间 |
| timestamp_raw | string/null | Received 中原始日期文本 |
| timezone_status | `known` / `utc_local_offset_unknown` / `missing` / `invalid` | `-0000` 使用第二种状态；缺少日期使用 missing |
| delay_seconds | number/null | 与前一跳的秒数差，保留负数 |
| parse_status | `complete` / `partial` / `unparsed` | complete 至少须有 from hostname、by hostname 和可确定时间；optional 子句缺失不降级 |

Endpoint：`hostname: string|null`、`ip: string|null`、`ip_candidates: string[]`、`ip_scope: public|private|loopback|link_local|documentation|reserved|ambiguous|unknown`。hostname 保留声明拼写；比较时才规范化。单个合法 IP 才填 ip；多个不同 IP 填 ip=null、ip_scope=ambiguous。RFC 文档地址使用 documentation，不填 private，也不视作真实公网来源。

RouteSummary：

- `candidate_received_count: integer`：物理头区中候选名称为 Received（大小写不敏感）的数量，包括 obsolete 候选。
- `recognized_received_count: integer`：Python 识别的数量，即 route 长度。
- `complete_hop_count: integer`：parse_status=complete 的数量。
- `total_observed_delay_seconds: number|null`：至少两跳且每跳时间已确定才填首尾差；零或一跳为 null。
- `chain_limit: integer`：本次启发式阈值，不是协议常数。

传输视图固定反转 recognized Received 的原始顺序；route_index 与 received_index 满足 `route_index + received_index = recognized_received_count + 1`。

## AuthenticationReport

```text
authentication
├── summary.spf / dkim / dmarc
├── assertions[]
├── received_spf[]
├── dkim_signatures[]
└── arc_headers[]
```

AuthSummary：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| status | `unknown` / `reported` / `mixed` / `unrecognized` | 无结果、有单一已知状态、多种状态、仅无法解释的状态 |
| reported_results | string[] | 按首次出现顺序去重的原始状态值；所有声明仍见 assertions |
| assertion_ids | string[] | 对应声明 ID |
| verified | boolean | 首版恒为 false |

AuthAssertion：`id`（auth-001…，按字段与子句顺序）、`header_id`、`authserv_id: string|null`、`method: string`、`result: string`、`properties: AuthProperty[]`、`reason: string|null`、`verified: false`、`trust: "unassessed"`。

AuthProperty：`name: string`、`value: string`；列表保留重复属性。known result 按方法区分：SPF 接受 none/neutral/pass/fail/softfail/temperror/permerror；DKIM 接受 none/pass/fail/neutral/policy/temperror/permerror；DMARC 接受 none/pass/fail/temperror/permerror。不认识的状态原样保留并产生字段解析缺陷；标准扩展支持以后的契约版本再更新。

`Authentication-Results: auth.example; none` 不产生 pass/fail assertion，所有概要为 unknown；原文保留。未知认证方法保留为 assertion，不参与三个概要。

其他头部使用独立证据记录：

- ReceivedSpf：`header_id`、`result: string|null`。只提取首个状态 token，原文见 headers；不覆盖 SPF summary。
- DkimSignature：`header_id`、`domain: string|null`、`selector: string|null`、`algorithm: string|null`、`verified: false`。只读取 d/s/a 元信息，不验证签名。
- ArcHeader：`header_id`、`name: string`。首版只收集 ARC-Seal、ARC-Message-Signature、ARC-Authentication-Results 的存在，不给 ARC pass 结论。

## Finding 与 ParseDefect

Finding：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| code | string | 稳定机器代码，见验收文档 |
| severity | `info` / `warning` | 首版没有自动“恶意/安全”的评级 |
| message | string | 简体中文可读解释 |
| header_ids / hop_ids | string[] | 证据引用，未知时为空列表 |
| details | object | 本规则特有的结构化参数，不包含可执行内容 |

ParseDefect：`code: string`、`message: string`、`header_id: string|null`。Python 缺陷 code 为 `PYTHON_<类名>`；MailTrace 结构化缺陷另使用明确 code，例如 INVALID_RECEIVED_DATE、UNSUPPORTED_AUTH_RESULT。defects 记录解析状态，warnings 记录规则发现；CLI 不重复打印同一个解析问题。

warnings 顺序固定：头区边界 → 单实例重复 → Received 解析 → 链长 → 逐跳 IP → 逐跳时间 → 链路衔接 → 回返。每项按原始字段/路由序号排列，同一证据与同一 code 不重复追加。

## 后续 API 与前端适配

API 返回同一 MailReport；输入校验错误使用 HTTP 错误响应，不包装成合法 report。核心报告不含 HTTP 状态码、上传路径、用户 ID 或 HTML。

前端使用 hop/header/auth 的稳定 ID 做关联：图边 → hop_id → header_id，风险卡 → header_ids/hop_ids，认证卡 → assertion_id → header_id。不根据数组下标猜测证据位置。数据库保存时可在报告外增加记录 ID，不改变输入决定的核心 ID。
