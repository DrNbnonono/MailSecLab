# OpenDKIM 不链 libunbound

镜像 `mailseclab-research-opendkim-libc`。`opendkim -V` 为 OpenDKIM Filter v2.11.0，`ldd` 没有 `libunbound`。容器替换为 `msl-opendkim`，地址仍是 `10.88.0.41`。配置仍是 `Nameservers 10.88.0.53`，`AuthservID mail.lab.test`，没有信任锚。

DNS 日志有来自 `10.88.0.41` 的 `cal._domainkey.lab.test` TXT 查询，dnsmasq 回答了这条记录。

| 邮件 | DKIM | DMARC | header.from |
| --- | --- | --- | --- |
| 合法签名 | `dkim=pass (2048-bit key; unprotected)` | `dmarc=pass (p=none dis=none)` | `lab.test` |
| From 插在签名前面 | `dkim=pass (2048-bit key; unprotected)` | `dmarc=fail (p=none dis=none)` | `evil.test` |

两封 SPF 都是 `spf=fail smtp.mailfrom=lab.test`，因为实验室 DNS 是 `v=spf1 -all`。`unprotected` 是没有 DNSSEC。插入那封的存档里仍是先 `from: Attacker <attacker@evil.test>`，再 `From: Author <author@lab.test>`。OpenDKIM 在能取到公钥时，这条插入仍判 pass。OpenDMARC 用的是第一条 From 的域。
