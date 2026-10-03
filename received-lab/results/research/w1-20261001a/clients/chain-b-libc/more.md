# 同一只 OpenDKIM 上的另外两封

二进制仍是不链 libunbound 的 2.11.0。两封 SMTP 都是 250。

`From : Extra <extra@evil.test>` 投递后被写成 `From: Extra <extra@evil.test>`，下面仍是 `From: Author <author@lab.test>`。

- OpenDKIM：`dkim=pass (2048-bit key; unprotected)`
- OpenDMARC：`dmarc=fail (p=none dis=none) header.from=evil.test`
- 存档再验：dkimpy fail，perl pass，go pass，rspamd none

第二条 From 插在签名下面，存档顺序是先 Author、后 Attacker。

- OpenDKIM：`dkim=fail reason="signature verification failed" (2048-bit key; unprotected)`
- OpenDMARC：`dmarc=fail (p=none dis=none) header.from=lab.test`
- 存档再验：dkimpy fail，perl fail，go fail，rspamd none

插在上面时这只 OpenDKIM 是 pass，插在下面是 fail。冒号前空格那封在规范化成两条普通 From 之后，OpenDKIM 仍是 pass，dkimpy 是 fail。

## 客户端

Roundcube 1.6.19 打开带真实认证结果的两封，预览都是 From Author，页面上没有 DKIM 或 DMARC 字样。

- uid 24，正文 `Case: preflight`，认证结果是 dkim=pass、dmarc=pass。回复的 To 是 `Author <author@lab.test>`。
- uid 25，正文 `Case: base-from-relaxed-n1-h1`，认证结果是 dkim=pass、dmarc=fail、header.from=evil.test。回复的 To 是 `Author <author@lab.test>`。全部回复的 To 是 Author，Cc 是 `recipient@receiver.test`。Attacker 不在收件人里。

SnappyMail 这次登录后停在身份编辑框，没有打开新邮件的回复窗口。收件箱列表里仍然能看到 Attacker 作为 Original subject 的发件人。
