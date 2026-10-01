# MailTrace 0.4 验证记录

日期：2026-10-02（Asia/Shanghai）。环境：Windows、PowerShell、Python 3.13.12、Node.js 22.22.2、npm 10.9.7、本机 Chrome。Python 3.11/3.12 与其他操作系统未在本次实测。

核心库 0.1.0、API/Web 0.4.0、报告契约 0.1。API 依赖见 `apps/api/requirements-dev.lock`，网页精确依赖见 `apps/web/package-lock.json`；本阶段不改变核心库安装依赖。

## 自动检查

| 检查 | 结果 |
| --- | --- |
| `.venv/Scripts/python.exe -m pytest tests -q` | 96 passed（80 核心、16 API） |
| `npm.cmd test`（apps/web） | 10 passed（6 图适配、4 代理） |
| `npm.cmd run typecheck` | 通过 |
| `npm.cmd run build` | 生产构建通过，页面、同源代理与 SVG 图标均生成 |

Python 测试有一条来自 Starlette TestClient 的 httpx 弃用提示；测试仍通过，运行接口不依赖 httpx。保留当前已验证锁定版本。

API 测试覆盖 JSON 与核心报告一致、上传字节一致、空输入、严格参数校验、验证错误脱敏、无 Content-Length 的实际字节上限、超大邮件、5000 位 Content-Length、无效 JSON、健康状态和 OpenAPI。图测试覆盖中继合并同时保留声明与 IP 证据、断链不补连接、未知节点不合并、回返不丢失以及展示上限不改动完整报告。

实现中发现并修复了 Route Handler 第二参数误用（Next.js 上下文对象被当作后端 URL）、超长 Content-Length 整数转换异常、共享中继丢失后续 IP 声明的问题，各自保留回归用例。

浏览器尺寸切换检查另发现受控节点未保存测量结果，导致图自适配使用旧视口。已接入节点状态更新，并按图框架的实际宽高重新适配；桌面→手机→桌面的节点几何尺寸复验通过。

## 真实浏览器

使用 Playwright CLI 连接实际生产网页 `127.0.0.1:3000` 与实际 Uvicorn API `127.0.0.1:8000`，未以固定 JSON 替代分析服务。全部输入为合成样本。

| 操作 | 结果 |
| --- | --- |
| 正常样本填入并分析 | 显示两跳、17 秒延迟、三项 pass 声明与私网提示 |
| 认证/风险证据链接 | 定位对应 Authentication-Results / Received 字段 |
| 下载 JSON | 实际文件包含 schema 0.1、完整头区 Base64、两跳与三项声明 |
| 邮件头搜索与时间线 | Authentication-Results 筛选仅一行，时间线展示 UTC 时间 |
| 可疑回返样本 | 显示回返与负延迟；输入变更时标记旧报告 |
| `.eml` 实际上传 | 51 跳报告，时间线第一页 50 条、第二页 1 条；字段列表可翻页 |
| 图中继声明 | 显示 192.0.2.25；两个按钮分别定位 header-001 与 header-002 |
| 键盘 Enter / Space | 边与节点均可更新证据面板 |
| 桌面 1440×1100、移动 390×844 | 截图检查；移动页面无横向溢出，窗口改变后自动适配图视口 |
| 服务错误（浏览器拦截模拟 502） | 显示可用的错误提示，不回显邮件 |
| 延迟请求期间清空 | 等待旧请求后报告不会重新出现 |

本地截图保存在忽略目录 `output/playwright/`（report-desktop.png、report-mobile.png、loop-timeline.png），浏览器控制记录位于 `.playwright-cli/`，均不提交含潜在用户输入的运行产物。

独立代码审查已完成并复查中继元数据修复，未发现剩余重要问题。DNS、主动认证验证、可信接收节点配置、历史数据库与账户系统仍属于后续阶段。
