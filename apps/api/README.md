# MailTrace API 0.5

FastAPI 是独立核心库的 HTTP 包装层。响应直接复用 `MailReport`（schema `0.1`），核心库无需安装 FastAPI 即可单独使用。

按仓库根目录 [README](../../README.md) 安装本地核心库、研究包、API 和精确依赖，然后从根目录运行：

```powershell
.\.venv\Scripts\python.exe -m uvicorn mailtrace_api.main:app --host 127.0.0.1 --port 8000
```

## 接口

| 方法与路径 | 输入 | 响应 |
| --- | --- | --- |
| `GET /api/v1/health` | 无 | 状态、API 版本、报告契约版本 |
| `POST /api/v1/analyze` | JSON：`raw_email` 字符串，`chain_limit` 正整数（默认 50） | 完整 MailReport |
| `POST /api/v1/analyze/file` | multipart：`file` 原始字节，`chain_limit`（默认 50） | 完整 MailReport |

JSON 示例：

```json
{"raw_email":"Subject: Sample\r\nFrom: alice@example.com\r\n\r\n", "chain_limit":50}
```

使用 PowerShell 调用真实样本：

```powershell
$mailText = [System.IO.File]::ReadAllText((Resolve-Path .\tests\samples\basic.eml))
$payload = @{ raw_email = $mailText; chain_limit = 50 } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/analyze -Method Post -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($payload))
curl.exe -F 'file=@tests/samples/basic.eml' http://127.0.0.1:8000/api/v1/analyze/file
```

交互式接口文档位于 `/docs`，OpenAPI 位于 `/openapi.json`。

## 边界与证据

邮件内容最多 10 MiB，整个 HTTP 请求体最多 12 MiB（包含 JSON 转义或 multipart 包装）。中间件检查实际收到的字节，无法通过省略 Content-Length 绕过上限。超限返回 413，无效或空输入返回 422；验证错误不会回显邮件内容。响应设置 `Cache-Control: no-store`。

JSON 文本按 UTF-8 分析；上传文件直接按原始字节分析，保留哈希、行号、字节偏移与头区 Base64。分析任务在线程池执行。以上单封接口不持久化邮件或报告；multipart 处理可能使用框架的临时文件，完成请求时关闭。

## 研究接口与归档

统一前缀 `/api/v1/lab`，模型见 [实验契约](../../docs/contracts/experiment-v0.1.md)。创建返回完整清单与指标摘要，分析报告和差分通过独立 GET 按需读取。

| 方法与后缀 | 输入 / 响应 |
| --- | --- |
| `POST /forge` | JSON `{case: CaseSpec, sweep?: SweepSpec}` → Manifest |
| `POST /compare` | multipart，多份同名 `files`，可选 JSON 字符串 `metadata` → Manifest |
| `GET /runs?cursor=<id>` | 每页 50 项，`items` 与 `next_cursor` |
| `GET /runs/{id}` | 核验后读取 Manifest |
| `POST /runs/{id}/reproduce` | 核验并复现，保存为新 ID |
| `GET /runs/{id}/snapshots/{snapshot_id}/report` | MailReport 0.1，原始头区 Base64 |
| `GET /runs/{id}/snapshots/{snapshot_id}/message` | 原始 `.eml` 下载 |
| `GET /runs/{id}/diffs/{diff_id}` | DiffReport 0.1，双侧证据引用 |
| `GET /runs/{id}/export/zip` | 完整实验产物 ZIP |
| `GET /runs/{id}/export/csv` | 指标 CSV，传输结果 not_measured |

`metadata` 必须与文件同序同数量，元素可填写 `label`、`capture_point`、含时区的 `captured_at`、`mta`、`mta_version`、`config_digest`、`capture_gap`。最后一项描述与前一个快照间的缺口；未提供 metadata 时使用文件名标签。比较只采用上传顺序。

```powershell
curl.exe -F 'files=@experiments/captures/01-before.eml' -F 'files=@experiments/captures/02-after.eml' http://127.0.0.1:8000/api/v1/lab/compare
$forgePayload = @{ case = @{ received_count = 2 }; sweep = @{ axis = 'received_count'; values = @(0,50,51,200) } } | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/lab/forge -Method Post -ContentType 'application/json' -Body $forgePayload
```

**研究接口自动保存原始邮件，包括正文。** 默认根目录为后端启动目录下的 `local-experiments`。可在启动前设置 `$env:MAILTRACE_EXPERIMENT_DIR = 'E:\MailTrace\local-experiments'`。归档使用新 ID、独立临时目录和完成后发布；读取、导出、复现检查哈希。不存在返回 404，损坏返回 409，无法读写返回 503；错误不回显邮件和磁盘路径。

单封最多 10 MiB，2–20 份比较或1–20 份生成，累计原始邮件最多 50 MiB。研究请求体单独限制 52 MiB，超限返回 413；原单封接口仍为 12 MiB。参数无效或尺寸不可实现返回 422；错误说明不可实现的尺寸原因及最小目标。取消 HTTP 等待不保证中断线程池中已开始的归档。生成与采集导入不执行 SMTP，未观测的 SMTP/日志/交付字段为 null。

默认离线，不查询 DNS，不验证 SPF/DKIM/DMARC，不配置可信接收节点。面向本机使用，本阶段未实现账户、数据库或公网部署配置。

测试从仓库根目录运行：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/api -q
```
