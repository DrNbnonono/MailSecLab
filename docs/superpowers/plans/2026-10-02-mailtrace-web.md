# MailTrace API/Web Implementation Plan

**Goal:** 从既有 Python 核心库交付可运行的本地邮件头可视化工作台。

**Architecture:** mailtrace-api 包装 analyze；Next.js 同源 Route Handler 代理固定后端，React 页面消费同一报告。核心库不依赖 Web 框架。

**Tech Stack:** FastAPI、Uvicorn、httpx、Next.js、React、TypeScript、Tailwind、React Flow。

按用户已有授权在本会话顺序执行；代码审查使用 requesting-code-review 技能。

## 任务

- [x] apps/api/pyproject.toml：安装 API 与开发依赖。
- [x] tests/api/test_api.py：先验证文本/上传契约、空输入、错误脱敏、大小上限、健康与 OpenAPI。
- [x] apps/api/src/mailtrace_api/{main,limits,schemas}.py：实现 request limit、接口和 no-store 响应。
- [x] apps/web/package.json、tsconfig.json、next.config.ts、postcss.config.mjs：固定工具链并安装。
- [x] apps/web/src/lib/report.ts：报告类型与纯图适配；使用 Node 测试真实跳 ID、断链、未知节点和绘制上限。
- [x] apps/web/src/app/api/analyze/route.ts：有上限、超时的同源代理，固定后端 URL，转发 bytes 和错误状态。
- [x] apps/web/src/components/：输入、图/时间线、证据、认证/异常、邮件头搜索与 JSON 下载；防止过期请求覆盖。
- [x] apps/web/src/app/{page,layout,globals.css}：暖灰/墨色/青绿工作台，键盘可操作与响应布局。
- [x] API 回归、前端单元/TypeScript/生产构建验证；启动本地服务。
- [x] Playwright 真实交互、移动端、错误态与截图检查。
- [x] 独立代码审查，修复问题并更新 README、依赖版本和验证记录。
- [ ] 提交并推送至 origin/tool/mailtrace，检查研究分支未改变。

每个行为先形成失败验证再实现；生产代码不以硬编码示例代替 API。边界失败保留在回归用例中。无关的数据库、DNS 和主动验证仍按后续版本计划。
