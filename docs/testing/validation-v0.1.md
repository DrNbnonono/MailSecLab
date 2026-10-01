# MailTrace 0.1.0 验证记录

日期：2026-10-01。Windows/PowerShell，Python 3.13.12。

## 核心行为

- 隔离 `.venv` 安装 `mailtrace-core[dev]` 成功。
- Pydantic 2.13.5、pydantic-core 2.46.5、pytest 9.1.1；完整开发依赖固定在根目录 requirements-dev.lock。
- `python -m pytest tests -q`：80 项通过。
- 实际分析 basic-example.eml 的完整 JSON 与设计契约示例逐字段一致，包括源 SHA-256、头区 Base64、字段偏移、证据 ID 和 17 秒延迟。
- 实际安装的 `mailtrace.exe` 可输出中文文本与 JSON。
- Python 模块编译检查通过。
- wheel 构建成功：mailtrace_core-0.1.0-py3-none-any.whl。
- 第二个干净环境仅安装 wheel 及固定运行依赖，没有 pytest/FastAPI；从 site-packages 导入并通过 `python -I` 与安装后的 CLI 核对完整契约输出。
- `pip check` 通过，无损坏的依赖关系。

核心功能提交：`b52f82a`。设计计划中建议的多个小步提交合并为本次首版功能提交；阶段验证与独立审查完成后提交。

## 独立审查与回归

独立代码审查复现的问题已修复，并通过回归验证：

1. 过深地址注释作为字段级 INVALID_ADDRESS，不能使整封分析崩溃。
2. Python 跳过的孤立续行或 Unix envelope 不再隐藏后续已接纳的字段。
3. 带引号 authserv-id、版本分隔符与属性点周围 CFWS 保留正确语义。
4. Received 带引号的队列 ID 与收件地址不截断。
5. 未闭合注释/引号显式记录 UNBALANCED_HEADER_SYNTAX。
6. IP 候选通过集合去重，保持原顺序；审查环境 5k/10k/20k 候选探测约为 0.060/0.121/0.286 秒，计时仅用于发现复杂度问题，不是性能保证。
7. UTC 转换溢出保留为日期缺陷，合法 quoted local-part 与日期注释正常处理。

独立复核后未发现剩余重大问题。没有向公网发信，也没有使用真实邮件测试。

## 验证边界

Python 3.11/3.12 与其他操作系统尚未在本机运行；最低版本来自使用的语言特性和依赖要求。首版不主动验证 SPF/DKIM/DMARC/ARC，不实现 DNS、数据库、HTTP API 或网页。解析失败与启发式提示不等价于证明邮件恶意或协议漏洞。
