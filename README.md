# MailTrace

Python 邮件头分析引擎与可视化工具。

项目以可独立导入的 Python 核心库为基础，按 CLI/JSON → FastAPI → Next.js 可视化 → DNS 与高级分析的顺序迭代。

当前阶段：**0.4.0（FastAPI + 可视化工作台）**，核心库仍为 **0.1.0**，JSON 契约为 **0.1**。支持粘贴邮件头、上传 `.eml`、Received 链路图与时间线、认证声明、异常提示、原始字段搜索及完整 JSON 下载。

## 启动网页

要求 Python 3.11+、Node.js 22+；在仓库根目录使用 PowerShell 安装：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\apps\api\requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .\packages\mailtrace-core -e .\apps\api
```

在第一个终端启动 API：

```powershell
.\.venv\Scripts\python.exe -m uvicorn mailtrace_api.main:app --host 127.0.0.1 --port 8000
```

在第二个终端启动网页：

```powershell
cd .\apps\web
npm.cmd ci
npm.cmd run dev
```

打开 [MailTrace 工作台](http://127.0.0.1:3000)；接口文档见 [FastAPI Docs](http://127.0.0.1:8000/docs)。生产运行可用 `npm.cmd run build` 后执行 `npm.cmd run start`。

网页通过同源代理连接本机 API。调整后端地址时，在 `apps/web/.env.local` 中设置 `MAILTRACE_API_URL`，参照 [环境变量示例](apps/web/.env.example)，然后重启网页服务。两端默认仅监听本机，报告不保存历史。

链路图每条边关联具体 Received 字段；中继节点保留前后声明的证据链接。没有声明的连接不会自动补画。图最多展示前 100 跳，时间线与字段列表每页 50 条，完整 JSON 保留全部报告内容。编辑输入后，旧报告会明确标记为待更新。

详细说明见 [API 文档](apps/api/README.md)、[网页文档](apps/web/README.md) 和 [本阶段验证记录](docs/testing/validation-v0.4.md)。

## 运行

在仓库根目录使用 PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .\packages\mailtrace-core
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\basic.eml
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\basic.eml --json
```

日常只使用核心库和 CLI，可以直接安装 `python -m pip install .\packages\mailtrace-core`，无需 pytest。Python 最低要求 3.11；本次验证环境与精确依赖版本见 [验证记录](docs/testing/validation-v0.1.md)。

```python
from pathlib import Path
from mailtrace import AnalysisOptions, analyze

report = analyze(Path("tests/samples/basic.eml").read_bytes(),
                 options=AnalysisOptions(chain_limit=50))
print(report.route)
print(report.authentication)
print(report.warnings)
print(report.model_dump_json(by_alias=True, indent=2))
```

认证 pass/fail 是邮件头中的声明，`verified` 恒为 false；默认没有可信接收节点配置。链路、环路、私网和时间提示都是可核查的调查线索。工具不会发送邮件、联网查询 DNS、保存输入或展开附件。

每个字段带 `header_id`、字节偏移和行号；`source.header_base64` 可还原原始头区。输入中的重复字段、畸形字段和 Python 未识别的候选内容均保留；正文不进入报告。Received 按字段声明的传输顺序展示，时间不会用于重排路由。

CLI 输入上限为 10 MiB，`--chain-limit` 默认 50，可调整。完成分析退出码为 0（包含有警告的报告）；文件/分析错误为 1，参数错误为 2。JSON 模式 stdout 只有一个报告，诊断写入 stderr。

## 合成样本与测试

`tests/samples/` 提供 basic、malformed-received、spf-fail、duplicate-from、loop、long-received-chain 六个合成样本。例如：

```powershell
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\loop.eml
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\long-received-chain.eml --chain-limit 50
.\.venv\Scripts\python.exe -m pytest tests --ignore=tests/api -q
```

测试涵盖报告契约、头区/正文边界、原始字节、折叠与重复字段、地址注释、时区与溢出、路由分析、认证声明与引号、CLI 的文件限制和控制字符转义。合成语料没有引用真实邮箱或邮件正文。

安装 API 开发依赖后，执行完整检查：

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
cd .\apps\web
npm.cmd test
npm.cmd run typecheck
npm.cmd run build
```

## 设计资料

| 文档 | 内容 |
| --- | --- |
| [首版设计](docs/superpowers/specs/2026-10-01-mailtrace-design.md) | 范围、模块边界、解析流程、CLI 和可视化信息设计 |
| [报告契约](docs/contracts/report-v0.1.md) | 稳定字段、证据位置、认证声明、后续 API/UI 关联 |
| [合成邮件](docs/contracts/basic-example.eml) | 两跳、17 秒延迟、私有 IP、SPF 声明的设计输入 |
| [JSON 示例](docs/contracts/report-v0.1.example.json) | 与合成邮件对应的完整拟定报告 |
| [验收矩阵](docs/testing/acceptance-v0.1.md) | 解析、规则、CLI 与边界行为 |
| [实施计划](docs/superpowers/plans/2026-10-01-mailtrace-core.md) | 首版八步落地任务与验证入口 |
| [API 与网页设计](docs/superpowers/specs/2026-10-02-mailtrace-web-design.md) | 接口、请求边界、同源代理与调查工作台 |
| [API 与网页实施计划](docs/superpowers/plans/2026-10-02-mailtrace-web.md) | 本阶段实现与验证任务 |

首版设计重点是保留原始邮件头证据、正确展示 Received 声明顺序，以及区分认证声明与主动验证。默认离线分析，邮件正文不进入报告。

Git：本地 `mailtrace` 跟踪远端 `tool/mailtrace`。研究分支的内容与历史独立保留。
