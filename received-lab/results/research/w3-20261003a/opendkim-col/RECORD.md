# OpenDKIM 仪器修复收口（任务 9，w3）

## 9a libunbound 因果对照（A/B 换装）

同一封 w3 `s0-strict-signed` 签名对照信经 auth-postfix 全链：

| 镜像 | AR dkim 判定 | dnsmasq 里来自 10.88.0.41 的查询 |
| --- | --- | --- |
| `opendkim-unbound:probe`（原版 USE_UNBOUND + unbound/dnsredir 入口） | `fail reason="key not found in DNS"` | **零**（发送前后无新增；unbound 日志仅 init 行） |
| `opendkim-libc`（无 libunbound 构建，现役） | `pass` | 正常查询 `cal._domainkey.lab.test`（05:00-05:09 的 sigprobe2 时段即证） |

根因坐实：**libunbound 构建的 DNS 查询路径不走容器配置的 Nameservers/unbound 转发，查询根本不出容器**；libc resolver 构建走 /etc/resolv.conf → 10.88.0.53 正常。w1 早期「OpenDKIM 不查公钥」的观察由此从现象升级为因果（镜像 A/B，其他运行参数相同）。

## 9b OpenDKIM 实例绑定列（此前缺列，本列补齐）

复用 w1 causal 的固定签名对（from-relaxed-n1-h1，签名字节不变）过 msl-auth-postfix（libc 版 OpenDKIM milter）：

| 变体 | OpenDKIM AR dkim |
| --- | --- |
| unchanged（单 From） | pass |
| 上方插第二 From（攻击者在签名实例之上） | **pass** |
| 下方插第二 From（攻击者在签名实例之下） | fail |

**OpenDKIM 2.11.0 = 底部实例选择**，与 perl/go 及 RFC 6376 §5.4.2 一致。与 w1 `clients/chain-b-libc/more.md` 的两例互证。至此实例绑定矩阵的 OpenDKIM 列闭合：DKIM/OpenDKIM/perl/go=底部、OpenDMARC=顶部、ENVELOPE=首元素、Roundcube=底部、SnappyMail=顶部。

证据：`okb-*.eml/.smtp.txt/.stored.eml`（本目录）；9a 的对照信 `/tmp/u9a-control.smtp.txt` 转录与 AR 已在文中引用。

## 遗留

parsedmarc 消费端验证仍阻塞：wheel 目录 31 个文件全部是 cp313-linux 平台 tag（用户机器 py3.13 环境下载），msl-verifiers 为 py3.11、WSL 3.10、Windows venv 亦不匹配。需按 cp311/manylinux 重新下载（命令已给出），届时补做「合法/伪造聚合报告的消费端探针」。
