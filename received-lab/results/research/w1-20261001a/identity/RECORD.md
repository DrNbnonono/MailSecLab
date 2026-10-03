# 身份字段

种子是 `causal/preflight/signed.eml`。DKIM-Signature 字节没有改。插入点在签名字段之后、原来的 From 之前。四家验证器读的是发送前的文件。投递走 `msl-auth-postfix`，当时的 milter 仍是拿不到实验室公钥的 OpenDKIM 2.11.0（libunbound）和 OpenDMARC 1.4.2。

## 发送前

| 插入 | 签名未变 | dkimpy | perl | go | rspamd |
| --- | --- | --- | --- | --- | --- |
| `Sender: Agent <agent@list.test>` | 是 | pass | pass | pass | pass |
| `Reply-To: Reply <reply@list.test>` | 是 | pass | pass | pass | pass |
| `Resent-From: Resent <resent@list.test>` | 是 | pass | pass | pass | pass |
| `From : Extra <extra@evil.test>` | 是 | pass | pass | pass | pass |
| 折叠的 `Reply-To: Reply` / `<reply@list.test>` | 是 | pass | pass | pass | pass |

这五个字段都不在 `h=` 里。冒号前带空格的 From 在发送前没有被四家当成第二条现代 From。

## 投递之后

OpenDMARC 的 `header.from`：Sender、Reply-To、Resent-From、折叠 Reply-To 都是 `lab.test`。`From : Extra` 被收下来之后写成了普通的 `From: Extra <extra@evil.test>`，`header.from=evil.test`。

对这份规范化后的存档再验：dkimpy fail，perl pass，go pass，rspamd none。分歧出现在 Postfix 把 `From :` 收成 `From:` 之后，发送前四家都是 pass。

## Roundcube 1.6.19 的回复

预览里的 From 链接都是 Author。

- 折叠 Reply-To 那封：回复的 To 是 `Reply <reply@list.test>`。全部回复的 To 仍是这个地址，Cc 是 `recipient@receiver.test`。
- `From : Extra` 规范化后的那封（uid 22）：回复的 To 是 `Author <author@lab.test>`，没有 Extra。
- 签名前插入 Attacker 的那封（uid 12，正文 `Case: base-from-relaxed-n1-h1`）：回复的 To 是 `Author <author@lab.test>`。全部回复的 To 是 Author，Cc 是 `recipient@receiver.test`。Attacker 不在收件人里。
- Sender 那封的地址标题里同时有 `author@lab.test` 和 `agent@list.test`，预览 From 仍是 Author。这封的回复按钮没有点成。

撰写身份是邮箱自己的 `bob <bob@msl-dovecot>`，不是原信的 From。

## 不带 libunbound 的 OpenDKIM

这次没有换成新二进制。`research/auth/opendkim-libc/Dockerfile` 要从 bookworm 源码编译，构建时 `deb.debian.org:80` 连不上，`build-essential` 没有装上，镜像里没有 `opendkim` 可执行文件。正在跑的 `msl-opendkim` 没有被替换，仍是带 `USE_UNBOUND` 的 2.11.0。所以这两封的 DKIM 行继续是 `key not found in DNS`，没有新的签名通过或失败。

## SnappyMail 2.38.2

收件箱列表里的发件人名字只有 Author 和 Attacker，没有 Agent、Resent 或 Extra。打开列表最后一封，短头部是 `Author <author@lab.test>`，旁边的红叉仍是 `dkim=fail reason="key not found in DNS"`。这封的回复窗口没有打开。
