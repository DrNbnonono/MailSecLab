# MailTrace API 0.4

FastAPI 是独立核心库的 HTTP 包装层。响应直接复用 `MailReport`（schema `0.1`），核心库无需安装 FastAPI 即可单独使用。

按仓库根目录 [README](../../README.md) 安装本地核心库、API 和精确依赖，然后运行：

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

JSON 文本按 UTF-8 分析；上传文件直接按原始字节分析，保留哈希、行号、字节偏移与头区 Base64。分析任务在线程池执行。应用不持久化邮件或报告；multipart 处理可能使用框架的临时文件，完成请求时关闭。

默认离线，不查询 DNS，不验证 SPF/DKIM/DMARC，不配置可信接收节点。面向本机使用，本阶段未实现账户、数据库或公网部署配置。

测试从仓库根目录运行：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/api -q
```
