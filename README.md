# MailTrace

Python 邮件头分析引擎与可视化工具。

项目以可独立导入的 Python 核心库为基础，按 CLI/JSON → FastAPI → Next.js 可视化 → DNS 与高级分析的顺序迭代。

当前阶段：**详细设计**。仓库已从 `research/received-trace` 继承内容中清理，首版核心库与 CLI 尚未实现；没有已完成的运行或产品测试结果。

## 设计资料

| 文档 | 内容 |
| --- | --- |
| [首版设计](docs/superpowers/specs/2026-10-01-mailtrace-design.md) | 范围、模块边界、解析流程、CLI 和可视化信息设计 |
| [报告契约](docs/contracts/report-v0.1.md) | 稳定字段、证据位置、认证声明、后续 API/UI 关联 |
| [合成邮件](docs/contracts/basic-example.eml) | 两跳、17 秒延迟、私有 IP、SPF 声明的设计输入 |
| [JSON 示例](docs/contracts/report-v0.1.example.json) | 与合成邮件对应的完整拟定报告 |
| [验收矩阵](docs/testing/acceptance-v0.1.md) | 解析、规则、CLI 与边界行为 |
| [实施计划](docs/superpowers/plans/2026-10-01-mailtrace-core.md) | 首版八步落地任务与验证入口 |

首版设计重点是保留原始邮件头证据、正确展示 Received 声明顺序，以及区分认证声明与主动验证。默认离线分析，邮件正文不进入报告。

Git：本地 `mailtrace` 跟踪远端 `tool/mailtrace`。研究分支的内容与历史独立保留。
