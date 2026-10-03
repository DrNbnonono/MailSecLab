# sigprobe2：DKIM 验证器 × obs-colon Received 交叉矩阵（w3-20261003a）

三基线（`h=from:to:subject:date:received`，d=lab.test，s=cal，relaxed/relaxed）× 三路径（norelay / osmtpd / postfix，中继后从 mailpit 取原始字节再验）× 四验证器（dkimpy 1.1.8 / perl Mail::DKIM / go-msgauth 0.6.8 / rspamd 3.4）。

## 矩阵（status；facts=存档里的 Received 形态计数）

| 基线 | 路径 | dkimpy | perl | go | rspamd | facts |
| --- | --- | --- | --- | --- | --- | --- |
| s0 strict 签名（对照） | norelay | pass | pass | pass | pass | strict=3 |
| s0 | osmtpd | pass | pass | pass | pass | strict=5 |
| s0 | postfix | pass | pass | pass | pass | strict=5 |
| **s1 obs 签名**（3 条 `Received :` 在签名时已存在） | norelay | **parse-error** | **fail** | **fail** | **fail** | obs=3 |
| s1 | osmtpd | parse-error | fail | fail | fail | **obs=3 保留** |
| s1 | postfix | fail | fail | fail | fail | strict=5（规范化） |
| **s2 obs 注入**（对 strict 签名后顶部插 1 条 obs，签名字节不变） | norelay | **parse-error** | pass | pass | pass | obs=1, strict=3 |
| s2 | osmtpd | **parse-error** | pass | pass | pass | **obs=1 保留** |
| s2 | postfix | **pass** | pass | pass | pass | strict=6（注入行被规范化） |

## 结论

1. **s1（12/12 格全灭）**：对 obs 形态字节构造的签名没有任何验证器/路径验过——perl/go/rspamd 能解析 obs 行但验签 fail（它们对 obs 行的 h= 选择或规范化与签名方不同）；dkimpy 直接拒解析。**无法用 obs 形态的 trace 构造可验证签名**（防御侧强结果）。诚实注：本实验室签名器对 obs 行的规范化是否完全合 RFC 未定论，失败的一致性（12 格）是可靠的经验事实。
2. **s2 norelay/osmtpd 精确复现 KB2 锚**：dkimpy 拒解析、perl/go/rspamd pass——签名后注入的异常头不破坏三家验签。**OpenSMTPD 的 obs 保留（L1）把 dkimpy 的拒解析一路带进邮箱（L3 传播）**：投递后的副本仍无法被 dkimpy 解析。
3. **s2 经 Postfix 全 pass（含 dkimpy）**：规范化把注入的 obs 行改写成 strict——dkimpy 的 parse-error 被**修复**，四家全部验过。**这是「修复制造/消除验证分裂」的最干净实例**：同一条注入消息，经不同中继后 dkimpy 的结论相反（osmtpd 后 parse-error vs postfix 后 pass）。

## 仪器记录（三轮调试后干净）

- 三个仪器 bug 及修复：(a) s2 曾从 s0 字节构造，Subject 沿用 s0 导致 mailpit 里两臂不可区分——改为独立 case 构造后签名再插 obs；(b) 同主题跨臂/跨次运行的 fetch 竞态——fetch 改为按中继标记（`by opensmtpd`/`by auth-postfix`）过滤 + 2s 预等待；(c) mailpit 删除端点为 `DELETE /api/v1/messages`（复数，全清）。
- 每格证据：输入 `.eml` + sha256（matrix.json 的 input_sha256）、SMTP 转录、存档 `.stored.eml`、verify_one 全量 stdout（matrix.json verifiers 字段）。
