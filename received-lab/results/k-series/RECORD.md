# K 系列实验记录（2026-09-07）

**核心问题**：同一个 DKIM 签名（同字节、同密钥 j1/lab.test/relaxed-relaxed），
在不同验证器眼里是否存在、是否有效？

**验证器**（三个异构独立实现）：
- dkimpy 1.1.8（Python，client 容器，dnsfunc 覆盖本地公钥记录）
- **perl Mail::DKIM**（CPAN 独立实现，DNS → dnsmasq 172.31.0.53）
- **go-msgauth v0.6.8 dkim-verify**（Go，DNS → dnsmasq）

**发现 0（基建）**：`opendkim-testmsg`（OpenDKIM 2.11 bookworm 打包）对**一切输入**
—— 包括最小合法报文 `A: b\r\n\r\nx\r\n` —— 一律报 `dkim_chunk(): Syntax error`
（工具/打包级损坏，与输入无关；已用源码 opendkim/opendkim-testmsg.c 确认其直接
fread→dkim_chunk，无输入协议前提）。**替换为 perl Mail::DKIM**。此发现本身有
工程价值：不要用 bookworm 的 opendkim-testmsg 做验证测试。

**基建**：mailnet 改为显式子网 172.31.0.0/16（172.30/16 与本机其它 compose 网络冲突），
dns 容器静态 IP 172.31.0.53，txt-record 由挂载的 dkim.pub.txt 在入口脚本生成；
Mailpit 加持久化（J 系列遗留）。所有驱动脚本内嵌 keeper（对抗 resource-saver 停 VM）。

## K1/K2 · 验证器差分矩阵（k1_matrix.csv）

| 语料 | dkimpy | perl Mail::DKIM | go-msgauth |
| --- | --- | --- | --- |
| KB1 干净签名 | pass | pass | pass（sanity ✓） |
| **KB2 签名后注入异常头** | **REFUSE-PARSE** | **pass** | **pass** |
| **KB3 重复 From+Subject** | **FAIL** | **pass** | **pass** |
| KB4 正文后第二头块 | pass | pass | pass |
| **KB5 l= + 正文头状行** | pass | pass | **Invalid: insecure body length tag** |
| j1_stored（截断后） | FAIL | fail（message altered） | Invalid（crypto/rsa 验证错误） |
| **j2_appended（l= 追加）** | **pass** | **pass** | **Invalid: insecure body length tag** |
| **j3_stored（淹没后）** | FAIL | **none（找不到签名）** | （无输出，解析即弃） |

## 结论

**H1（边界差分）成立**（KB2）：同一签名报文，dkimpy 拒绝解析、perl/go 判
**有效签名**。J3 的"淹没"报文并非在所有验证器里都死 —— 在宽容验证器下签名依然有效，
且异常头（Receíved 伪造 Received）依然存在于头区：**dkimpy 的用户看到"无效/拒解析"，
go/perl 的用户看到"来自 lab.test 的有效签名 + 一条伪造 Received"**。

**H2（选取差分）成立**（KB3）：重复 From/Subject 时 dkimpy 判 FAIL 而另两家 pass
—— dkimpy 用最后一实例做验证哈希，perl/go 用第一实例。攻击者签名第一组头、
展示第二组头（From: mallory@evil.example），即可让宽松验证器显示"有效签名"而
实际展示的 From 未被覆盖。

**K2/l= 结论**（KB5 + j2_appended）：`l=` 前缀签名的追加攻击（J2）只在
**容忍 l= 的验证器**（dkimpy/perl）上有效；go-msgauth 一律拒绝
（`insecure body length tag`）。反之，攻击者若想让 go-msgauth 判 pass 就不能用 l=，
追加内容必被检出。**同一攻击在不同验证器上有效性相反。**

**总图景（四层分歧齐备）**：transport（3B/E3）≠ parser（3C）≠ verifier（K1/K2）
≠ security（H/F1）。"这封邮件是否带有有效签名"不是字节流属性，而是
**(字节流, 验证器) 二元组属性**。

## 事故与教训

1. opendkim-testmsg 全面损坏（见上），换 perl 实现。
2. `172.30.0.0/16` 与宿主既有 compose 网络冲突 → 换 172.31/16。
3. **Bash 工具链会吃掉一层反斜杠** —— 本次与 G 系列的所有 `\r\n` heredoc 灾难
   同根因。以后多行转义一律用 Write/Edit 工具直写文件。
4. go-msgauth 包路径：`cmd/dkim-verify`（不是 `dkim/cmd/dkimverify`），
   二进制名 `dkim-verify`。

## 遗留

- K3 rspamd 全栈（DNS/DMARC/SPF 联判）：canary 结果见本轮输出；无论稳定与否，
  均可先用 `network:none` + 静态 hosts 的折中方案做 R_DKIM 判定（dkimpy 公钥
  已可注入 dnsmasq，rspamd 指向 dnsmasq 即可，无需公网）。
- KB3 的 From 选取需再用 i=/x= 标签交叉验证（记录验证器内部选头逻辑）。
- K5 走私阳性对照（Exim 4.92）保持暂缓。
[20:00:40] == K3: rspamd full stack (dnsmasq + maps pinned) ==
[20:00:57] rspamd up (networked + dnsmasq)
  KB1-clean.signed -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_PERMFAIL dmarc=-
  KB5-l= -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_PERMFAIL dmarc=-
  j2_appended-l= -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_PERMFAIL dmarc=-
  j1_stored-truncated -> score=1.0 action=no action dkim=- dmarc=-
  j3_stored-drowned -> score=8.4 action=add header dkim=- dmarc=-
[20:01:02] == K3 DONE ==
[20:03:01] == K3: rspamd full stack (dnsmasq + maps pinned) ==
[20:03:46] rspamd up (networked + dnsmasq)
  KB1-clean.signed -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_TEMPFAIL dmarc=-
  KB5-l= -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_TEMPFAIL dmarc=-
  j2_appended-l= -> score=3.4 action=no action dkim=DKIM_TRACE;R_DKIM_TEMPFAIL dmarc=-
  j1_stored-truncated -> score=1.0 action=no action dkim=- dmarc=-
  j3_stored-drowned -> score=8.4 action=add header dkim=- dmarc=-
[20:03:59] == K3 DONE ==
[20:06:48] == K3b: rebuild dns (TXT split), rescan with --ip external ==
[20:07:13] rspamd up
  KB1-clean.signed -> score=4.5 action=greylist dkim={'DKIM_TRACE': ['lab.test:?'], 'R_DKIM_TEMPFAIL': ['lab.test:s=j1']}
  KB5-l= -> score=4.5 action=greylist dkim={'DKIM_TRACE': ['lab.test:?'], 'R_DKIM_TEMPFAIL': ['lab.test:s=j1']}
  j2_appended-l= -> score=4.5 action=greylist dkim={'DKIM_TRACE': ['lab.test:?'], 'R_DKIM_TEMPFAIL': ['lab.test:s=j1']}
  j1_stored-truncated -> score=4.5 action=greylist dkim={'DKIM_TRACE': ['lab.test:?'], 'R_DKIM_TEMPFAIL': ['lab.test:s=j1']}
  j3_stored-drowned -> score=10.9 action=add header dkim={'R_DKIM_NA': None}
[20:07:54] == K3b DONE ==
[20:11:53] == K3 matrix: rspamd with working DNS (--dns at creation) ==
  KB1-clean.signed -> score=4.3 action=greylist dkim={'R_DKIM_ALLOW': ['lab.test:s=j1'], 'DKIM_TRACE': ['lab.test:+']}
  KB3-dup-from -> score=11.4 action=add header dkim={'R_DKIM_REJECT': ['lab.test:s=j1'], 'DKIM_TRACE': ['lab.test:-']}
  KB5-l= -> score=4.3 action=greylist dkim={'R_DKIM_ALLOW': ['lab.test:s=j1'], 'DKIM_TRACE': ['lab.test:+']}
  j2_appended-l= -> score=4.3 action=greylist dkim={'R_DKIM_ALLOW': ['lab.test:s=j1'], 'DKIM_TRACE': ['lab.test:+']}
  j1_stored-truncated -> score=7.0 action=add header dkim={'R_DKIM_REJECT': ['lab.test:s=j1'], 'DKIM_TRACE': ['lab.test:-']}
  j3_stored-drowned -> score=12.4 action=add header dkim={'R_DKIM_NA': None}
[20:12:10] == K3 MATRIX DONE ==

## K3 · rspamd 全栈（canary 通过 + DNS 接入）

**Canary 结果**：`maps.rspamd.com→127.0.0.1`（即时拒绝）+ 开网条件下 rspamd
**稳定运行 300s+** —— 证实 exit-255 = "map 拉取挂死→崩溃"，即时失败则无恙。
compose 已固定 `extra_hosts: maps.rspamd.com:127.0.0.1` + `dns: 172.31.0.53`。

**DNS 基建**：dnsmasq 容器（172.31.0.53）提供 `j1._domainkey.lab.test` TXT
（p= 超过 TXT 单串 255 字节上限，需拆分为多段字符串——RFC 6376 允许拼接）；
rspamd 必须在**容器创建时**注入 `--dns`（运行后覆写 resolv.conf 无效——其
resolver 在启动时读取）。

**K3 矩阵**（rspamc --ip 192.0.2.200 模拟外部发件人，k3_rspamd.csv）：

| 语料 | R_DKIM | 分数/动作 |
| --- | --- | --- |
| KB1-clean | **ALLOW**（trace +） | 4.3 greylist |
| **KB3-dup-from** | **REJECT**（trace −） | 11.4 add header |
| KB5-l= | **ALLOW** | 4.3 greylist |
| j2_appended-l= | **ALLOW** | 4.3 greylist |
| j1_stored-truncated | **REJECT**（message altered） | 7.0 add header |
| j3_stored-drowned | **NA**（找不到签名） | 12.4 add header |

## K 系列最终验证器全景（4 验证器）

| 语料 | dkimpy | perl | go | rspamd |
| --- | --- | --- | --- | --- |
| KB1 clean | pass | pass | pass | ALLOW |
| KB2 异常头注入 | 拒解析 | pass | pass | （未测，预期同 perl/go） |
| **KB3 重复 From** | FAIL | pass | pass | **REJECT** |
| **KB5/j2 l= 追加** | pass | pass | **Invalid** | **ALLOW** |
| j1 截断 | FAIL | fail | Invalid | REJECT |
| j3 淹没 | FAIL | none | 无输出 | NA |

**结论**：三处实证差分 ——
1. 重复 From：go/perl 判 pass（验证第一实例），dkimpy/rspamd 判 FAIL/REJECT
   （第二实例未签名）→ "有效签名"与否取决于验证器选头策略。
2. l= 追加：go 一律拒绝，其余全部放行 → 追加攻击有效性因验证器而异。
3. 淹没/截断：所有验证器一致失败，但失败形态不同（fail/none/无输出）。
