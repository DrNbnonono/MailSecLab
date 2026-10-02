# OpenDKIM / OpenDMARC

Postfix `msl-auth-postfix` 的 `smtpd_milters` 从 `inet:msl-rspamd:11332` 改成 `inet:msl-opendkim:8891, inet:msl-opendmarc:8893`。`milter_default_action=tempfail`。两家 milter 都在监听，SMTP 回复是 250。

版本：OpenDKIM Filter v2.11.0，编译选项含 `USE_UNBOUND`。OpenDMARC Filter v1.4.2，`WITH_SPF`。

两边的 AuthservID 都设成 `mail.lab.test`，这样 OpenDMARC 的 TrustedAuthservIDs 能读到 OpenDKIM 写的结果。软件包不写这一项时，OpenDKIM 用自己的主机名。实验室 DNS 的 SPF 是 `v=spf1 -all`，DMARC 是 `p=none`。这是实验区记录，不是软件包默认策略。

`chain-b/legit.stored.eml` 与 `chain-b/from-insert-before.stored.eml` 是第一次结果。后面的 `chain-b2` 到 `chain-b5` 是同一对邮件的重复发送，DKIM 原因没有变化，不另算发现。

之后又把容器内的 DNS 查询转到本机 unbound，再转发到 `10.88.0.53`。进程加载了转向库，dnsmasq 仍然没有 `cal._domainkey.lab.test` 的查询。`chain-b-fwd3/legit.stored.eml` 仍是 `dkim=fail reason="key not found in DNS"`。

两封的 DKIM 行都是：

`dkim=fail reason="key not found in DNS" header.d=lab.test header.s=cal`

同网络命名空间里 `dig @10.88.0.53 cal._domainkey.lab.test TXT` 能返回公钥。验证时刻的 dnsmasq 日志没有 `10.88.0.41` 对这个名字的查询。OpenDKIM 使用 libunbound。把 Nameservers、resolv.conf 和 root.hints 指到 `10.88.0.53` 之后仍然没有这条查询。因此这里没有签名通过或签名失败的差分，只有「公钥没有被这个验证器取到」。

OpenDMARC：

- 合法邮件 `header.from=lab.test`
- 插入在前 `header.from=evil.test`
- 两封 `spf=fail smtp.mailfrom=lab.test`
- 两封 `dmarc=fail (p=none dis=none)`，SMTP 250，LMTP 已保存
