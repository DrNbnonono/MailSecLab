# 大头对 MUA 的代价

`msl-auth-postfix`：`hopcount_limit=50`，`message_size_limit=10240000`，`header_size_limit=102400`。每封只发一次，没有循环。

| 输入 | 字节 | SMTP | 到 Dovecot |
| --- | --- | --- | --- |
| 10 条 Received | 1,354 | 250 | 到了。IMAP 取出 1,979 字节，脚本内计时 0.0 秒，整次 0.219 秒 |
| 55 条 Received | 6,754 | `554 5.4.0 Error: too many hops` | 没有 |
| 单字段 X-Big 200,000 字节 | 200,182 | 250 | 到了。队列里是 60,499 字节，日志有 `breaking line > 998 bytes` |
| 约 1MB 的短 X-Fill | 999,990 | `451 4.7.1` milter-reject | 没有 |
| 约 4MB 的短 X-Fill | 3,999,980 | `451 4.7.1` milter-reject | 没有 |

Dovecot 内存从 3.7 MiB 到 11.1 MiB，上限 256 MiB。Roundcube 约 60 MiB，SnappyMail 约 55 MiB，这几封之后没有变化。

MUA 没有看到「无限变长」的头。跳数过多在 Postfix 就被 554 挡住。更大的头块被 milter 以 451 挡下。单字段超过行长限制时，Postfix 先截短再投递。
