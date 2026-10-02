# 客户端展示

运行 `w1-20261001a`。同一封已保存邮件在两家客户端里的 From 不一致。截图在本目录。

镜像：

- Roundcube `roundcube/roundcubemail:1.6.19-apache`，`sha256:5c7331ca2686f1622117f3fc5901c58b098d6a2e2a08b858257e592e6106e2fb`
- SnappyMail `djmaze/snappymail:v2.38.2`，`sha256:5e3d990438809a8a49f8ac5758db03e858e6e9fc0e369e1f9e474f7664079905`

登录都是 IMAP `bob` / `lab-bob`，主机 `msl-dovecot:143`，无 TLS。这些邮件没有 Reply-To。

## 链 A：rspamd milter，存储件没有 Authentication-Results

插入在前的那封正文是 `Case: base-from-relaxed-n1-h1`，头里先是 `from: Attacker <attacker@evil.test>`，再是 `From: Author <author@lab.test>`。

- Roundcube 预览 From 是 Author，链接 `mailto:author@lab.test`。页面上没有 DKIM、SPF 或 DMARC 字样。`roundcube-from-insert.png`。
- SnappyMail 列表和打开后的 From 都是 Attacker，链接 `mailto:attacker@evil.test`。页面上没有认证警告。`snappy-insert-before.png`，列表见 `snappy-inbox.png`。
- 合法对照正文 `Case: preflight`，两家都显示 Author。`roundcube-legit.png`、`snappy-legit.png`。

## 链 B：OpenDKIM 2.11.0 与 OpenDMARC 1.4.2

存储件带有 Authentication-Results。OpenDKIM 两封都是 `dkim=fail reason="key not found in DNS"`。实验室 DNS 上 `cal._domainkey.lab.test` 的 TXT 能被 dig 读到；验证当时 dnsmasq 没有来自 `10.88.0.41` 的这条查询。这个失败是验证器没有取到已发布的公钥，不能当成签名字节被判无效。

OpenDMARC 的 `header.from`：单封 From 为 `lab.test`，插入在前的那封为 `evil.test`。SPF 两封都是 `spf=fail smtp.mailfrom=lab.test`，因为本实验室 DNS 写成 `v=spf1 -all`。DMARC 是 `p=none`，两封都投递了。

- SnappyMail 打开插入在前的邮件，From 仍是 Attacker，地址旁有红色叉。叉的 title 是上述 `dkim=fail ... header.b=eWjCDNXR`。`snappy-chainb-attacker.png`。
- 同一客户端打开合法邮件，From 是 Author，红色叉的 title 是 `dkim=fail ... header.b=hFE/jxe6`。`snappy-chainb-author.png`。红色叉两封都有，没有把 Attacker 和 Author 区分开。
- Roundcube 打开 IMAP uid 12（正文仍是 `Case: base-from-relaxed-n1-h1`），预览 From 是 Author，`mailto:author@lab.test`。预览页没有认证字样。`roundcube-chainb-uid12.png`。
- Roundcube 的 Headers 对话框列出了 Authentication-Results，其中包括 `dmarc=fail ... header.from=evil.test` 和 `spf=fail`。`roundcube-headers.png`。

收件箱列表里，Roundcube 把这些 Original subject 都标成 Author；SnappyMail 把插入在前的标成 Attacker。
