# MailTrace

Python 邮件头分析引擎与可视化工具。

项目以可独立导入的 Python 核心库为基础，按 CLI/JSON → FastAPI → Next.js 可视化 → DNS 与高级分析的顺序迭代。

当前阶段：**0.5.0（邮件头实验工作台）**，核心库与研究包均为 **0.1.0**。保留单封分析，并加入参数化样本生成、单变量扫描、逐跳字段差分、自动归档与复现；MailReport、ExperimentManifest 和 DiffReport 使用各自的 **0.1** 契约。

## 启动网页

要求 Python 3.11+、Node.js 22+；在仓库根目录使用 PowerShell 安装：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\apps\api\requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .\packages\mailtrace-core -e .\packages\mailtrace-lab -e .\apps\api
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

网页通过同源代理连接本机 API。调整后端地址时，在 `apps/web/.env.local` 中设置 `MAILTRACE_API_URL`，参照 [环境变量示例](apps/web/.env.example)，然后重启网页服务。两端默认仅监听本机；单封分析不保存历史，研究操作自动归档。

链路图每条边关联具体 Received 字段；中继节点保留前后声明的证据链接。没有声明的连接不会自动补画。图最多展示前 100 跳，时间线与字段列表每页 50 条，完整 JSON 保留全部报告内容。编辑输入后，旧报告会明确标记为待更新。

详细说明见 [API 文档](apps/api/README.md)、[网页文档](apps/web/README.md) 和 [研究阶段验证记录](docs/testing/validation-v0.5.md)。

## 研究工作台 0.5

打开 [MailTrace Lab](http://127.0.0.1:3000/lab)：

1. **样本生成**：控制 Received 数量、连续/回返、日期、SP/HTAB 折行、CRLF/LF、冒号前空格、重复字段与顺序；精确设置最长行与头区大小，单变量批量生成。
2. **逐跳对比**：上传原始 `.eml` 并明确排序、填写采集标签；仅比较相邻快照。查看新增、删除、值变化、格式变化、重排及不确定对应，双侧定位字段字节与哈希。
3. **实验历史**：每页 50 项，重新打开、核验并复现为新实验，下载完整 ZIP、指标 CSV 与清单 JSON。

**研究操作自动保存原始邮件（包含正文）**到后端启动目录下的 `local-experiments/<id>/`。从仓库根启动默认是 `E:\MailTrace\local-experiments`；目录已加入 Git 忽略。设置后端 `MAILTRACE_EXPERIMENT_DIR` 可更换根目录。先在独立临时目录写完再发布，读取和复现前核验哈希。取消页面等待不保证撤销后台归档，请刷新历史核查。

研究包可以独立使用，无需 FastAPI 或网页：

```powershell
.\.venv\Scripts\python.exe -m pip install --no-deps -e .\packages\mailtrace-lab
.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\received-baseline.json --sweep .\experiments\cases\received-counts.json
.\.venv\Scripts\mailtrace-lab.exe diff .\experiments\captures\01-before.eml .\experiments\captures\02-after.eml .\experiments\captures\03-gap.eml
.\.venv\Scripts\mailtrace-lab.exe reproduce <experiment_id>
```

`--store <directory>` 是全局选项，放在 forge/diff/reproduce **之前**；它优先于环境变量。

```python
from mailtrace_lab import CaseSpec, SweepSpec, forge_case, compare_headers, ExperimentStore

sample = forge_case(CaseSpec(received_count=51, seed=0))  # 纯函数，无文件读写
diff = compare_headers(before_bytes, after_bytes)       # 原始字节，不重编码展示文本
run = ExperimentStore().forge(CaseSpec(), SweepSpec(axis="received_count", values=[0,50,51,200]))
```

每封最多 10 MiB，每次最多 20 个样本/快照、累计 50 MiB；Received 最多 10,000 条。研究代理请求上限 52 MiB、超时 120 秒。扫描组不是传输链，生成成功不代表 MTA 接受；本轮不自动发送邮件。TraceJudge 复用现有异常规则并在快照分析中单独展示调查提示，HeaderDiff 只描述可核验变化。

参见 [统一实验格式与归档说明](docs/contracts/experiment-v0.1.md)、[生成用例](experiments/cases/README.md)、[合成采集快照](experiments/captures/README.md)。

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

认证 pass/fail 是邮件头中的声明，`verified` 恒为 false；默认没有可信接收节点配置。链路、环路、私网和时间提示都是可核查的调查线索。核心单封分析不发送邮件、联网查询 DNS、保存输入或展开附件；研究包按上述规则归档。

每个字段带 `header_id`、字节偏移和行号；`source.header_base64` 可还原原始头区。输入中的重复字段、畸形字段和 Python 未识别的候选内容均保留；正文不进入报告。Received 按字段声明的传输顺序展示，时间不会用于重排路由。

CLI 输入上限为 10 MiB，`--chain-limit` 默认 50，可调整。完成分析退出码为 0（包含有警告的报告）；文件/分析错误为 1，参数错误为 2。JSON 模式 stdout 只有一个报告，诊断写入 stderr。

## 合成样本与测试

`tests/samples/` 提供 basic、malformed-received、spf-fail、duplicate-from、loop、long-received-chain 六个合成样本。例如：

```powershell
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\loop.eml
.\.venv\Scripts\mailtrace.exe analyze .\tests\samples\long-received-chain.eml --chain-limit 50
.\.venv\Scripts\python.exe -m pytest tests --ignore=tests/api --ignore=tests/lab -q
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
| [研究工作台设计](docs/superpowers/specs/2026-10-02-mailtrace-lab-design.md) | 生成、单变量扫描、逐跳差分与自动归档 |
| [实验契约 0.1](docs/contracts/experiment-v0.1.md) | 模型、尺寸口径、证据匹配、归档与复现 |

首版设计重点是保留原始邮件头证据、正确展示 Received 声明顺序，以及区分认证声明与主动验证。默认离线分析，邮件正文不进入报告。

Git：本地 `mailtrace` 跟踪远端 `tool/mailtrace`。研究分支的内容与历史独立保留。
