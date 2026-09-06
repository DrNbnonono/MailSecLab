# J 系列实验记录（2026-09-06 深夜）

**问题**：传输层的静默头截断 / `l=` 语义 / 头区边界异常，与**真实 DKIM 签名验证**的交互。
**工具**：dkimpy 1.1.8（client 容器内，构建期代理 pip 安装）；验证用 `dnsfunc` 覆盖注入
本地公钥记录（无 DNS）；密钥 openssl 2048-bit，relaxed/relaxed，d=lab.test s=j1。
链路：postfix1 → postfix2 → postfix3 → mailpit（标准链）。Mailpit 加持久化存储
（`MP_DATA_FILE=/data/mailpit.db` + volume —— 此前 VM 重启即丢信，致多次取证据失败）。

## J1 · 超长折叠头截断 × DKIM（假设成立）

构造：150KB 折叠 `X-Gen` 头（> header_size_limit）+ 正常身份头，DKIM 签名
`h=from:to:subject:message-id:x-gen`（无 l=，整个头与正文都在保护内）。

| 阶段 | 大小 | 验证 |
| --- | --- | --- |
| 签名后（中继前） | 154,562 B | **pass** |
| 三跳中继后（Mailpit 存储） | 103,283 B（X-Gen 被静默截断至 ~101.7KB） | **FAIL** |

**结论**：Postfix 对超长头的静默截断会**破坏 DKIM 签名**——对防守方这是好事
（截断可被认证层发现），但注意签名失败只会让 DKIM 判为 fail，报文仍投递。

## J2 · l= 前缀签名 + 正文追加（假设成立，RFC 6376 §3.7 已知弱点实证）

| 阶段 | 验证 |
| --- | --- |
| 签名（l=True，正文 "benign signed body"） | pass |
| 正文追加 101B 垃圾（"WIN A PRIZE visit spam.example..."） | **pass** |
| 中继存储后 | **pass** |

**结论**：`l=` 前缀签名的报文，正文可以无限追加未经签名的任意内容（钓鱼文案/
广告注入）而签名保持有效。攻击者用自己域名签名即可让带签名垃圾通过
"有 DKIM 签名"的过滤逻辑。

## J3 · 签名后注入头区终结异常（"淹没"攻击）

流程：签干净报文（h=from:to:subject:message-id）→ **在签名前注入一条 Receíved
异常头**（未签名的头可任意插入，签名不受影响——插入本身不破坏 h= 覆盖）→ 中继。

| 阶段 | 结果 |
| --- | --- |
| 干净签名验证 | pass |
| 注入异常后，dkimpy 直接解析 | **MessageFormatError（拒绝解析）** —— 签名后无法验证 |
| 经 postfix1 中继 + Mailpit 存储 | 头区只剩异常行；**DKIM-Signature/From/To/Subject/Message-ID 全部沉入正文**；Mailpit 补 Bcc/Message-ID 并把整封当正文 |
| 存储版验证 | **FAIL**（bh= 覆盖的正文已吸收全部原头内容，必然失配） |
| 仅删除异常行 | 仍 FAIL（正文已变，不可恢复） |

**结论**：异常头注入对 DKIM 的效果是"**淹没**"——签名字节完整保留在存储正文中
（md5 与原签名一致），但消息永久不可验证。防守方失去 DKIM pass 信号；攻击者同样
失去它。J3 同时证明：**dkimpy 在签名边界就拒绝 V007 型异常头**（无法为畸形头签名），
所以此类报文必然是无签名报文——与 Phase 3C 的解析差分（go/node 仍按头解析）合并，
构成"认证缺失 + 解析分裂"的组合画像。

## 事故与方法论

1. dkimpy 1.1.8 `sign(self, selector, domain, privkey, ...)` 参数序与常见文档相反，
   且 selector/domain/key 均需 **bytes**；parse_pem_private_key 同样要求 bytes PEM。
2. dnsfunc 覆盖必须双参 `(name, timeout)`；verify 吞掉 dnsfunc 异常静默返回 False。
3. Mailpit 无持久化时 VM 重启即丢信 —— 已加 `MP_DATA_FILE` 持久化；raw 视图会
   规范化 LF 并重编码 UTF-8（对比字节时注意）。
4. Mailpit `/api/v1/message/{ID}/raw` 才是原始报文（`/view` 与 `/message` 返回摘要 JSON）。

## 数据文件

`j1_*.eml`（签名/存储对）、`j2_*.eml`（l= 三态）、`j3_*.eml`（clean/signed/injected/
stored/repaired/drownfixed）、`dkim.key`、`dkim.pub.txt`（测试密钥，公开值）。
