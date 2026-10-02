# Exim 4.92 阳性对照

镜像 `mailseclab-research-exim492`，由 `debian:buster-slim` `sha256:bb3dc79fddbca7e8903248ab916bb775c96ec61014b3d02b4f06043b604726dc` 构建。容器内 `exim --version`：

`Exim version 4.92 #5 built 04-Jan-2024 20:07:16`

只发送了现有 I1 的两种分隔，各一封：`i1-exim492-crlf.payload`、`i1-exim492-lf.payload`。接收端是本实验室 Mailpit `10.88.0.25:1025`。启动日志有一行 `exim user lost privilege for using -C option`。投递到 Mailpit 的 Received 仍写着 Exim 4.92，主机名 `exim492.lab.test`。

`summary.json` 里 LF 的 `smuggled: 1` 是计数器把正文里的 `X-Case-ID: SMUG-...` 当成了第二封。以保存的 `.eml` 为准，Mailpit 每种分隔各有一封，信封都是 `alice@sender.lab.test`。

CRLF（`\r\n.\r\n`）：`i1-exim492-crlf-1fp91jkwR1U9xP9QN2ry8l.eml`。正文只有 `body of first message`。SMTP 在第一封 `250 OK id=1xCXYa-00000K-5Y` 之后又回答了 `250 OK`、`250 Accepted`，接着 `554 SMTP synchronization error`。没有第二封到达 Mailpit。

LF（`\n.\n`）：`SMUG-i1-exim492-lf-45DXYMs3fDmagXqdi5oqwG.eml`。主题仍是 `I1 first i1-exim492-lf`。注入的 `MAIL FROM:<eve@evil.example>` 留在这一封的正文里。连接以 `221` 结束。没有单独的第二封。
