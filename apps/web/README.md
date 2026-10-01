# MailTrace Web 0.4

Next.js App Router、React、TypeScript、Tailwind CSS 与 React Flow 构成邮件头调查工作台。输入与报告只存在当前页面内存中，不写入 localStorage 或历史数据库。

先启动 [API](../api/README.md)。在本目录运行：

```powershell
npm.cmd ci
npm.cmd run dev
```

打开 `http://127.0.0.1:3000`。生产模式运行 `npm.cmd run build`，再运行 `npm.cmd run start`。默认仅监听 `127.0.0.1`。Node.js 要求 22+，实际验证为 22.22.2，依赖由 `package-lock.json` 固定。

## 使用

1. 粘贴原始邮件/邮件头，或点击/拖入 `.eml` 文件。合成样本按钮只填入内容，点击分析后才调用 API。
2. 在链路图或时间线中选择声明；右侧证据展示原始字段、行号、字节范围、时间与协议。中继节点上的两个字段按钮分别定位接收与来源声明。
3. 在认证、异常与邮件头标签中查看声明、调查提示和可搜索的折叠原文。证据链接均定位具体字段。
4. 下载完整 JSON 以核查头区 Base64 和全部链路。文件名仅使用输入哈希前缀。

编辑输入会标记旧报告；清空、替换文件或改动内容会取消待完成请求，旧请求不会覆盖新输入。服务错误显示在输入区。

图中显示前 100 跳，并提示省略数量；时间线与邮件头每页 50 条；单字段预览最多 65,536 字符。完整 JSON 不受这些展示限制。已知连续中继可合并，未知与断开的节点保持独立；回返节点按出现次数显示，不会被合成唯一节点。

## 代理配置

浏览器仅访问同源 `POST /api/analyze`。Next.js 在服务器端代理固定后端路径：JSON → `/api/v1/analyze`，multipart → `/api/v1/analyze/file`。文件内容以字节流转发，不做文本重编码。

后端默认 `http://127.0.0.1:8000`。需要调整时复制 `.env.example` 为 `.env.local` 并修改 `MAILTRACE_API_URL`，重启服务。该变量不暴露给浏览器。代理请求体限制 12 MiB，上游超时 45 秒；响应不缓存，不在错误中回显输入。

## 检查

```powershell
npm.cmd test
npm.cmd run typecheck
npm.cmd run build
```

单元测试覆盖图的证据 ID、断链、未知节点、回返、中继 IP、绘制上限及真实 Route Handler 的代理行为。浏览器验收记录见 [validation-v0.4.md](../../docs/testing/validation-v0.4.md)。
