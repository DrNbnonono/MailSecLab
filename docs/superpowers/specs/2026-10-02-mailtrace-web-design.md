# MailTrace API 与可视化工作台

依据已经确认的 MailTrace 设计，在用户授权下同时实现 V0.3 API 与 V0.4 Web。核心库和报告 schema_version=0.1 保持可独立使用。

## 结构与接口

- `apps/api/`：可安装的 FastAPI 应用 `mailtrace_api`，调用既有 analyze，不复制解析规则。
- `POST /api/v1/analyze`：JSON `{raw_email: string, chain_limit?: positive integer}`，返回原始 MailReport。
- `POST /api/v1/analyze/file`：multipart 的 file 和可选 chain_limit，按原字节分析 .eml，不能先转为 UTF-8 文本再分析。
- `GET /api/v1/health`：只返回服务状态与版本，不返回输入。
- `.eml` 内容上限 10 MiB；HTTP 请求体上限 12 MiB，涵盖 JSON/multipart 编码开销。ASGI 层在解析请求前核验实际接收的大小，不只相信 Content-Length。超限 413，空输入/参数错误 422，类型错误按 HTTP 验证错误处理。
- 校验错误不回显请求内容，报告响应 `Cache-Control: no-store`。核心分析在线程池运行，避免同步解析阻塞事件循环。上传临时文件在请求结束关闭，不保留上传记录。
- 默认只绑定 127.0.0.1。前端服务器固定代理 API 地址，不从浏览器输入任意远端 URL；使用同源请求。服务器地址通过 MAILTRACE_API_URL 设置，默认 http://127.0.0.1:8000。

## 网页与交互

`apps/web/` 使用 Next.js App Router、TypeScript、Tailwind CSS 与 React Flow。主色为暖灰白，深墨色标题、青绿色选中状态、琥珀色异常；等宽字体用于主机、协议和原始头区。字体使用本地可用字体，不要求联网加载字体。

桌面为输入侧栏和报告工作区；工作区包含概要、链路/时间线切换、证据详情，以及认证/异常/邮件头视图。窄屏改为纵向排列，图独立缩放，不使整页横向溢出。

1. 粘贴邮件原文，或上传 .eml。上传通过二进制文件原样提交。
2. 提供正常两跳与循环示例，并明确标为“合成样本”；切换样本只填入输入，不暗中分析用户内容。
3. 点击“分析邮件头”后展示 loading；成功用新报告替换旧结果，失败显示可操作错误；输入变化期间旧报告标记为上一份结果，避免把旧报告当作当前输入结果。
4. React Flow 每条可观察传输边对应 hop_id。相邻两跳主机声明衔接时共享一个中继节点；不衔接时保持两个端点，不补画连接。回返使用独立发生位置的节点实例，避免循环边挤压不可读；它们仍保留相同主机声明。
5. 点击边、时间线条目或警告定位 header_id；证据区显示原始值、行号、字节偏移、recognition 与结构化细节。
6. 认证卡明确“头部声明 / 未主动验证”，显示多个来源，不把 pass 画成邮件安全评分。
7. 邮件头可搜索和展开；保留重复实例、未知候选与 parser defects，默认显示所有字段。
8. 用户可下载本次完整 JSON。不会自动写 localStorage、数据库或上传历史；刷新清空输入。
9. 点击清空终止待完成请求并清除报告、输入、文件与证据选择。每个请求有独立 ID，旧响应不得覆盖更新的输入或报告。

## 图的性能与数据

报告完整保留所有跳。图最多绘制前 100 跳并提示实际数量，时间线与完整 JSON 提供全量证据；时间线/头区按 50 项分页，避免长链生成大量 DOM。选中图外证据仍可通过时间线或警告查看。未知节点明确标为未知，不认定真实发送源。

时间统一展示 UTC，详情同时展示原始日期文字。负延迟保持负值并标记异常。无 Received 的报告显示空态，不报安全结论。

## 验收

- 原有核心测试继续通过；API 文本/上传返回与核心库相同的报告，保留 bytes/text input_kind 差异。
- 检查无 Content-Length 的流式超限、声明长度超限、空文件、坏 JSON、字段类型与正整数阈值、响应不缓存、错误不回显邮件。
- 前端 TypeScript 与生产构建通过；浏览器验证样本分析、粘贴、二进制上传、链路/时间线、警告/认证原文定位、头部搜索、JSON 下载、清空、错误态与窄屏。
- 独立代码审查后修复重大问题，验证过程与实际版本记录到 docs/testing。

## 参考

- [FastAPI 文件上传](https://fastapi.tiangolo.com/tutorial/request-files/)
- [Next.js Route Handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route)
- [React Flow](https://reactflow.dev/learn)
- [Tailwind 与 Next.js](https://tailwindcss.com/docs/installation/framework-guides/nextjs)
