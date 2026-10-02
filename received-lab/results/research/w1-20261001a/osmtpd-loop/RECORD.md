# OpenSMTPD 同构环

两台 OpenSMTPD 6.8.0p2 互相 `relay`。一封种子是普通 `Received:`，一封是 `Received :`（冒号前一个空格）。停在第一次 `500 5.4.6 Routing loop detected`。接受次数上限 160，180 秒只作安全上限，两次都没用到。

镜像 `received-lab-opensmtpd:latest`，`sha256:4a2ae1cb6e850b48e4d9b40784bb9cab511afab6029352a998f49e07d6dd30e4`。

每跳新增的行都是普通 `Received:`，例如：

```
Received: from 89d5cba2a23b (msl-osloop-b.mailseclab-research-net [10.88.0.5])
	by msl-osloop-a.lab.test (OpenSMTPD) with ESMTP id 2210bfa7
	for <bob@lab.test>;
	Fri, 2 Oct 2026 11:06:39 +0000 (UTC)
```

| 种子 | 停止 | 秒 | 一侧在 PermFail 前的成功投递 | 捕获邮件里的 Received |
| --- | --- | --- | --- | --- |
| `Received:` | `5.4.6` | 71.4 | a.log 49 次 Ok，然后 PermFail；b.log 在 DATA 回 500 | 退信里夹着原信 |
| `Received :` | `5.4.6` | 50.7 | b.log 49 次 Ok，然后 PermFail；a.log 在 DATA 回 500 | 99 条普通 `Received:`，种子 `Received :` 仍在最底部 |

空白种子没有被改写成普通 `Received:`，也没有让环越过同一条 `5.4.6`。OpenSMTPD 自己盖上的戳仍被计数。上次 60 秒日志里普通种子已经出现 `5.4.6`、空白种子还没有，是因为那次空白环更慢（85 对 109 次接受），不是空白变体不计自己新增的行。

原始日志和捕获邮件在本目录的 `loop-normal/` 与 `loop-obs/`。计数见 `counts.json`。
