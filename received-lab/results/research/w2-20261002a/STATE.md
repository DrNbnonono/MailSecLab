# w2-20261002a 实验状态快照（2026-10-03）

## 栈状态（相对 w1 初始的差异清单）

| 组件 | 变更 | 原因/备注 |
| --- | --- | --- |
| auth-postfix | `smtpd_milters` 末位加 `inet:msl-rspamd:11332` | B 线评估器分裂实验 |
| rspamd | spf/dmarc 模块启用；`local_networks=127.0.0.0/8`；`actions reject=999, add_header=6`；asn/surbl/rbl `enabled=false` | 提速与评测启用；阈值放开为保投递取证 |
| opendmarc | `HistoryFile /var/run/opendmarc/opendmarc.history`；RejectFailures 已复原 false | rua 盲区取证 |
| msl-dns（RUN_ID=w1） | extra-dns.conf：IDN 受害域（p=reject+rua+授权记录）、evil.test/元字符区公钥、`local=/lab.test/`、MX/A | 各战役；恢复默认栈时按此表回滚 |
| dovecot | 无变更（无 sieve 包，装不了） | |

## 资产清单

- 工具族 `research/lib/`：eai_matrix / eai_enforce / qname_probe / ar_probe / void_probe / nfd_probe / rua_aggregate / dns_fwd / imap_probe / hdrfuzz / hdrfuzz2 / sig_probe
- 已知结果表：`hdrfuzz2/known-outcomes.json`（29 元组，自动加载）
- 声明文档：NOVELTY_CLAIM.md（+CVE 横幅）、UPSTREAM.md、RECORD.md、LAB_JOURNAL.md（全时序）

## 机制家族收敛现状（From 层，271 例后）

M1 不可提取→无盖章（59）/ M2 EAI 空洞（25）/ M3 literal（15）/ M4 dotless（31）/ M5 rspamd 群组静默（58）/ M6 正常（52）+ 签名轴（11 形态仅 obs-colon 存活）。**From 层机制级封闭。**

## 累计规模（2026-10-03 收）

w2 run 总案例数 ≈ 2500（hdrfuzz 30 + hdrfuzz2 240 + hdrfuzz3 900 + hdrfuzz4 1008 全叉积 + hdrfuzz5 144 签名轴 + 定向探针 ~60）。工具族 + known-outcomes.json（29 元组）。两个披露候选：① rspamd 群组/domain-literal DMARC 静默；② 外域 AR 存活 + SnappyMail 徽章渲染。两个阴性关闭：Resent/Sender 显示替代、obs 路由地址。

## 栈状态补充（2026-10-03 recfuzz2 后）

- auth-postfix 新增 `transport_maps = hash:/etc/postfix/transport`（capture@lab.test → smtp:[msl-mailpit]:1025）——保留供原始捕获复用；恢复默认栈时删除并 reload。
- exim 容器现由镜像 `received-lab-exim:v3` 运行（双网：received-lab_mailnet + 研究网），路由=msl-auth-postfix:25，日志在 `/var/log/exim4/main`（非 mainlog）。
- msl-mailpit 已接入研究网（SMTP 1025 / API 8025，容器内名 msl-mailpit）。
- opensmtpd 路由=msl-auth-postfix:25（默认）。

## 回滚完成记录（2026-10-03 任务 7 收尾）

- exim route→msl-auth-postfix:25 ✓、opensmtpd relay→msl-auth-postfix:25 ✓、postfix transport_maps 清空 ✓（capture 捕获路由已撤）。
- parser-node 容器保留运行（diffrun parse 目标，复用时直接可用）；msl-mailpit 保留在研究网（已在 STATE 记录）。
- 保活任务 exec_c1499e76 已停止（见下）。
- rspamd asn/surbl/rbl=off、actions reject=999、dmarc/spf 模块启用等 w2 实验态**未回滚**（后续实验继续用；如需纯净默认栈按本文件回滚表逐项处理）。

## 活动后台任务（勿忘）

- **Windows 侧 WSL 保活**：exec_c1499e76（每 15s docker exec 防休眠）——实验全部结束后停掉。
- WSL/Docker 曾反复休眠（2026-10-03 事故，毁掉 hdrfuzz5 两轮）；长实验必须保活。

## 本轮（2026-10-03）两个新主攻面

1. **身份字段另一半**：Resent-\* / Sender / Reply-To 文法轴（ENVELOPE 有 Sender/Reply-To 槽可做快速 oracle；Resent 显示需浏览器定向探针）。
2. **AR 头形态轴**：伪造 AR 的存活矩阵（外域 authserv-id / obs 冒号 / 无 id / 折叠）——若任何形态存活到邮箱且 SnappyMail 渲染其为徽章，则 ar3 徽章伪造复活。
- 报告消费端（parsedmarc）受离线装包阻塞，本轮先验证阻塞再记录。
