# Received: 头增长与 hopcount_limit 边界实验报告

- 日期:2026-08-30(第一阶段)/ 2026-08-30(第二阶段:RFC 无界增长路径验证)
- 环境:WSL2 + Docker Desktop,拓扑 `client → postfix1 → postfix2 → postfix3 → mailpit`,全部流量在 `mailnet` 内部网络
- Postfix 版本:3.7.11(Debian bookworm),`hopcount_limit = 50`(默认),TLS 关闭,`mydestination` 为空(纯中继)
- 样本:全部通过 `client` 容器内的 Python 脚本直连 SMTP 注入预置头部,唯一 `X-Case-ID` 用于追踪

---

## 0. 环境修复(实验前置)

原始配置存在两个问题,已修复并重建镜像:

| 问题 | 根因 | 修复 |
| --- | --- | --- |
| 邮件卡在 P1 队列:`Host not found for name=postfix2` | Debian 的 Postfix 默认将 smtp/smtpd chroot 到 `/var/spool/postfix`,chroot 内无 `resolv.conf`,Docker DNS(127.0.0.11)不可达 | entrypoint 启动前 `cp /etc/{resolv.conf,hosts,services} /var/spool/postfix/etc/` |
| `docker logs` 看不到任何投递日志,无法取证 | 容器内无 syslog 守护进程,`maillog_file` 未设置 | entrypoint 增加 `postconf -e "maillog_file = /dev/stdout"` |

修复后 `docker logs postfixN` 可完整观测每条消息的 `smtpd/qmgr/cleanup/smtp/bounce` 链路,是本实验的取证基础。

---

## 1. 里程碑验证(prompt.md 三项判定)

① **普通邮件进入 Mailpit**:swaks 基线邮件在三个 Postfix 均为 `status=sent`,Mailpit 收到(证据:`results/baseline_raw.eml`)。

② **每跳新增一个 Received,最新在最上**:

```text
Received: from postfix3.lab.test by mailpit.lab.test (Mailpit) with SMTP   ← Mailpit 自加
Received: from postfix2.lab.test by postfix3.lab.test (Postfix) id 57F1E8805E
Received: from postfix1.lab.test by postfix2.lab.test (Postfix) id 51C6588059
Received: from client.lab.test   by postfix1.lab.test (Postfix) id 4A41F88053
```

③ **预置 10 个 Received 全部保留**:最终 `received_count=14 = 10(伪造)+ 3(Postfix)+ 1(Mailpit)`。

**重要基线事实:Mailpit 也是 SMTP 端点,会自己追加一个 Received 头。因此 Mailpit 中统计到的最终数量 = N + 4。**

---

## 2. 实验一:预置 Received 数量 N = 0~100 扫描(hopcount_limit = 50)

数据:`results/scan_limit50.csv`(101 行,每行附 `results/logs/<case>.*.log` 证据)。

### 2.1 结果分布

| queue_status | N 范围 | 数量 |
| --- | --- | --- |
| delivered | 0 ≤ N ≤ 46 | 47 |
| bounced_not_delivered(客户端仍收到 250,随后上游退信) | N = 47, 48 | 2 |
| rejected_at_data(客户端在 DATA 结束时直接收到 554) | 49 ≤ N ≤ 100 | 52 |

### 2.2 临界区明细(N = 45~50)

| case | N | P1 DATA 回复 | P1 | P2 | P3 | 结局 |
| --- | ---: | --- | --- | --- | --- | --- |
| C045 | 45 | 250 | relay=sent | relay=sent | relay=sent | 投递,最终 Received = 49 |
| C046 | 46 | 250 | relay=sent | relay=sent | relay=sent | 投递,最终 Received = **50** |
| C047 | 47 | 250 | relay=sent | relay=bounced | **hopcount exceeded** | P2 生成 DSN,退信送达 Mailpit |
| C048 | 48 | 250 | relay=bounced | **hopcount exceeded** | 无流量 | P1 生成 DSN |
| C049 | 49 | **554** | hopcount exceeded | 无流量 | 无流量 | DATA 阶段被 P1 拒绝 |
| C050+ | ≥50 | 554 | hopcount exceeded | — | — | 同上,100% 在 P1 被拒 |

### 2.3 实测拒绝规则(不查文档、纯实验得出)

**任一 Postfix 节点:当「入站 Received 数 + 本机即将新增的 1 条」≥ hopcount_limit 时拒绝;**
即一条消息在一个 Postfix 节点能携带的 Received 总数上限为 `hopcount_limit − 1`。

- limit=50:链上最后允许的总数 49。N=46 时 P3 看到 48 入站 +1 = 49,通过;N=47 时 49+1=50,拒绝 → 三跳链恰好 N ≤ 46 可投递。
- limit=8 交叉验证(`results/scan_limit8.csv`):公式预测投递边界 N ≤ 4、N=5 P3 拒、N=6 P2 拒、N=7 P1 DATA 拒——实测完全吻合,证明该规则随 limit 线性缩放,不是 50 特有的巧合。

### 2.4 拒绝的协议与日志特征(取证指纹)

- SMTP 层:`554 5.4.0 Error: too many hops`(Postfix 3.7 实测为 **5.4.0**,不是老文档常见的 5.4.6),发生在 **end-of-DATA**,即 MAIL/RCPT 全部成功、`data=0/1`。
- 日志层:拒收节点在 MAIL 阶段已分配队列 ID,随后 `cleanup: warning: <QID>: message rejected: hopcount exceeded`。
- **每个节点的 hopcount 检查是独立、有损的**:若上游已受理(客户端拿到 250),下游拒绝时由上游产生 DSN(`postfix/bounce: sender non-delivery notification: <新QID>`),DSN 携带原邮件头作为附件沿链路继续传送并最终进入 Mailpit。攻击者视角:预置 47~48 个 Received 时,**发件人会收到内容包含全部伪造头的退信**——伪造头不仅没被过滤,还被反向放大传播。

---

## 3. 实验二:头字段名变体(X-Received / Received-SPF / 大小写)

| 用例 | 预置头 | N | 结果 | 结论 |
| --- | --- | ---: | --- | --- |
| XR100 | X-Received | 100 | 投递,真实 Received 仅 4(3+1) | X-Received **不参与** hop 计数 |
| RS100 | Received-SPF | 100 | 投递,同上 | Received-SPF **不参与** hop 计数 |
| RC046/47 | rEcEiVeD | 46 / 47 | 46 投递、47 在 P3 被拒——与标准 Received **逐字节一致的行为** | 头字段名匹配**大小写不敏感**(符合 RFC 5322) |
| RD046/47 | RECEIVED | 46 / 47 | 同上 | 同上 |

注:变体 CSV 中 `final_received_count=4` 是计数脚本的显示假象(仅精确匹配 `Received:`);100 个 X-Received 头被原样透传到 Mailpit(已验证 raw 中 100 条全在)。Postfix 的 hop 计数对字段名做大小写折叠,但对头名的"前缀相似性"(X-Received、Received-SPF)不做任何宽松匹配。

---

## 4. 实验三:真实邮件循环(P3 → P1 回环,hopcount_limit = 8)

配置:`postfix3 relayhost = [postfix1]:25`,三节点 `hopcount_limit=8`(运行时 postconf 注入,实验后已恢复)。发送一封普通邮件(N=0),`results/loop/LOOP01.*.log`。

时间线(全部队列 ID 实测):

```text
hop 1  P1 BC9F487FC7 → P2      hop 5  P2 CAF1287FC7 → P3
hop 2  P2 C2B3588067 → P3      hop 6  P3 CBCF588067 → P1
hop 3  P3 C826887FC7 → P1      hop 7  P1 CCD0C87FC7 → P2  ✗ P2 拒绝(7+1=8 ≥ 8)
hop 4  P1 CA23588067 → P2           554 5.4.0 too many hops

P1 生成 DSN1(发件人 <>):CF2FB88068 → P2 D00A887FC7 → P3 D10FE88067 → P1 D210C87FC7
   → P2 D2E1188067 → P3 D3ABE87FC7 → P1 D479488067 → P2 ✗ 第二次 hopcount exceeded
DSN1 的发件人为空 <>,Postfix 对空发件人消息不再生成退信 → 循环终止,日志安静收尾
```

要点:
- 终止循环的是 **hopcount 检查本身**(第 8 跳),而不是 Postfix 的 `loop detection`(地址重写检测在这套拓扑里不生效,因为 `mydestination` 为空、没有本地投递,消息永远只是"路过")。
- 每绕一圈,消息体积持续膨胀:原邮件 411B(hop1)→ 1647B(hop7);DSN1 3646B → 4882B。**在 limit 足够大时,循环同时是放大器(带宽)与垃圾头注入器。**
- 双退信被空发件人规则自然截断:整个循环恰好产生 2 条死信 + 0 条进 Mailpit,系统自愈,无管理员干预。
- Mailpit 全程未收到任何消息(邮件从未走完 P3 的下一跳)。

---

## 5. 阶段性结论

1. **Postfix 的 hop 计数语义**:只统计字段名大小写不敏感等于 `Received` 的头部,计数包含本机新增的一条,拒绝阈值是 `总数 ≥ hopcount_limit`,可用上限 `limit − 1`。hopcount 检查发生在 cleanup(end-of-DATA),与 SMTP 会话的 MAIL/RCPT 阶段无关。
2. **检查点非原子**:多跳链路中"谁先拒绝"取决于消息到达该节点时的累计数;上游节点已经 250 的部分无法撤回,只能靠 DSN 补救,DSN 本身又成为新的循环/放大载体。
3. **伪造头的传播**:被拒消息的伪造 Received 头会通过 DSN 完整回传给(可能伪造的)发件人地址;而成功投递路径上,46 个伪造头可以一路存活到收件方——若下游反垃圾依赖 Received 链分析,这些条目没有置信度标记可供区分。
4. **大小写不敏感是正确实现**,但也意味着基于精确字符串 `Received:` 的下游解析器会低估 hop 数(本实验中 rEcEiVeD 计入 Postfix 计数,但脚本计数器如不折叠大小写就会漏计)——对写分析工具是个直接提醒。

## 6. 第二阶段:RFC 缝隙的无界增长路径验证

问题:对照 RFC,什么东西能让头部**绕开 hopcount 无限制增长**?本节先列出 RFC 依据,再用 16 个实测用例逐条验证(`results/phase2.csv`)。

### 6.1 RFC 依据(条款均为本地核对原文)

| 条款 | 原文要点 | 对头部增长的含义 |
| --- | --- | --- |
| RFC 5322 §3.6 字段次数表 | `trace`、`optional-field`、`resent-*`、`comments`、`keywords` 均为 **unlimited** | 除少数 max-1 字段外,协议不限头数量 |
| RFC 5321 §4.5.3.1.8 | 该节标题为 **Recipients Buffer**,在"不得按消息头中出现的收件人数拒信"的语境下 invokes the general principle: relaying servers "**MUST NOT** ... perform validation tests on message header fields" | 是一般性原则的引用而非针对任意头校验的专门条款;实验上 Postfix 3.7.11 中继也确实不强制 RFC 5322 的字段次数约束 |
| RFC 5321 §3.7.2 | 接收方 "**MUST NOT** reject mail based on the format of a trace header field" | 畸形 Received 也必须"极健壮地"硬吃 |
| RFC 5321 §6.3 环检测 | "SHOULD use a large rejection threshold, **normally at least 100**" —— SHOULD 建议而非 MUST | 计数是推荐做法;Postfix 默认 50 低于该建议值 |
| RFC 5321 §4.5.3.1 / §4.5.3.1.7 | 实现应"impose **no limits**";消息 MUST 至少接受 64K | 协议层不存在"头总大小"上限 |
| RFC 5322 §2.2.3 | 折叠后 "no length restriction ... indeterminately long" | 单头可以任意大 |
| RFC 5321 §4.4 | 每跳 MUST 前插 Received,MUST NOT 删除/修改既有 Received | 头部是 append-only 日志,只增不减 |

### 6.2 结果总表(16 用例)

| 用例 | 注入内容 | 发送字节数 | SMTP | 结局 | 最终标准 Received | 关键观察 |
| --- | --- | ---: | --- | --- | ---: | --- |
| RB010/100/300 | Resent 块 ×10/100/300(40/400/1200 头) | 2K/19K/56K | 250 | 全部投递 | 4 | **hopcount 对 Resent 完全失明**,300 块原样到达 |
| FC090 | 折叠 Received ~90KB × 3 | 276K | 250 | 投递 | 7 | 计数 7,27 万字节头部畅通 |
| FC150 | 折叠 Received ~150KB × 1 | 153K | 250 | 投递 | 5 | 单头被**静默截断至 101701 B**(≈`header_size_limit`=102400),条数仍算 1 |
| FC500 | 折叠 Received ~90KB × 5 | 459K | 250 | 投递 | 9 | 尺寸线性扩张到 46 万字节,hopcount 仍只有 9 |
| DS050 | Subject × 50 | 5.6K | 250 | 投递 | 4 | RFC 5322 max-1 字段重复 51 条无阻 |
| DM050 | Message-ID × 50 | 5.8K | 250 | 投递 | 4 | 同上 |
| DC100 | Comments × 100(对照) | 11K | 250 | 投递 | 4 | unlimited 字段畅通 |
| EW005 | `Received :`(冒号前空格)× 5 | 0.8K | 250 | 投递 | **9** | 被 Postfix **规范化为标准 Received 并计数** |
| EWT05 | `Received<TAB>:` × 5 | 0.8K | 250 | 投递 | **9** | Tab 同样被吞掉、规范化、计数 |
| EW100 | `Received :` × 100 | 11K | 554 | P1 拒收 | — | 空格伪装**无效**:直接触发 hopcount exceeded |
| ET050 | `Receíved:`(UTF-8 同形)× 50 | 5.7K | 250 | 投递 | 4 | 不计数;但**头部区在此终结**(见 6.4) |
| AF100 | ARC 三元组 × 100(300 头) | 44K | 250 | 投递 | 4 | 310 个逻辑头,hopcount 读数 4 |
| RW046 | 46 个 Received + 100 个 X-Received | 9.0K | 250 | 投递 | 50 | 边界与垃圾头**完全无关** |
| RW047 | 47 个 Received + 100 个 X-Received | 9.1K | 250 | P3 拒 + P2 退信 | — | 边界与第一阶段分毫不差(47+3=50≥50) |

### 6.3 路径 A/B/D/F:计数盲区被全部证实

- **B(Resent 块)**:RFC 5322 §3.6.6 语义上的"重新进入传输系统"痕迹字段,300 块(1200 个头、含 300 个 Resent-Date)投递成功,最终标准 Received 仍是 4。协议认可的"准 trace"完全在 hopcount 视野之外。
- **D(重复 max-1 字段)**:51 个 Subject / 51 个 Message-ID 畅通,印证 §4.5.3.1.8"中继不得校验头字段"。
- **F(ARC 三元组)**:真实转发器每跳 3 头(RFC 8617)的**名字模拟**——310 个逻辑头 vs hopcount 读数 4,**背离系数约 77×**,且随链长线性放大。限定:本用例只证明 ARC-named 头不参与 hopcount,不涉及 ARC 链连续性、AMS/AS 签名验证、`cv=` 等安全语义;那些问题需要真实 ARC signer/verifier(Phase 5)。
- **边界独立性(RW)**:100 个 X-Received 上下夹带,46/47 的临界行为与纯净环境完全一致。即:**垃圾头不改变拒绝边界,只在边界之下无限堆积**。

### 6.4 路径 E 的意外发现:两种完全相反的行为

**空格/Tab 变体(计数、规范化)**:`Received : xxx` 与 `Received<TAB>: xxx` 被 Postfix 3.7 按"名字含尾随空白"宽松解析:投递时被**原地规范化**为标准 `Received:`(EW005 raw 中 5 条 fake 全部变成 `Received: from fake000...`),并且计入 hopcount(×100 时 P1 直接 554)。结论:**对 Postfix 而言,空白伪装不是绕过手段**。

**UTF-8 同形名(不计数,但触发 header-termination 容错路径)**:`Receíved:` × 50 不被计数——需要严谨说明的是:RFC 5322 §3.6.8 要求 field-name 为 printable US-ASCII,而发送端以裸 UTF-8 字节发送(`\xc3\xad`)且未声明 SMTPUTF8,因此这一行**不是合法的 RFC 5322 头字段**,不应表述为"绕过"。实测现象是:Postfix 3.7.11 的 cleanup 在这条非法行处**直接终结头部区**,其后的所有内容被静默重新解释为正文。ET050 最终报文的头部区只剩 8 个字段:

```text
Bcc / Message-ID(Mailpit)/ Return-Path / Received × 4 / X-Case-ID
```

我们自己注入在伪造块之后的 `From:`、`To:`、`Subject:`、`Message-ID:` **全部进了正文**(已核实 raw)。这意味着一条畸形头就够把后续所有合法头"一刀切掉"——对下游基于头的处理(SPF/DKIM/DMARC、反垃圾规则、归档索引)是一个**头部致盲原语**;报文看起来"投递正常",但收件方实际看不到任何业务头。

### 6.5 路径 C:尺寸维度实测

- `header_size_limit`(102400)的行为:超限单头**不拒信、不丢头**,静默截断(150KB → 101701B),条数照常 +1。
- 尺寸维度与计数维度完全解耦:45 万字节的合法折叠头部(hopcount=9)畅通无阻。到 `message_size_limit`(默认 10MB)之前,尺寸增长没有别的闸门。

### 6.6 第二阶段结论

对"如何让头部无限制增长"的最终回答(全部经实验证实):

1. **条数维度**:hopcount 只数"名字(空白容忍、大小写折叠后)恰好是 Received"的头。`Resent-*` 块、ARC/Authentication-Results、任意 X- 头、重复的 max-1 字段——**条数无界,直到 `message_size_limit`(默认 10MB)**。
2. **尺寸维度**:RFC 5322 折叠允许单头任意长,Postfix 的 `header_size_limit` 只做静默截断(单头 ~100KB 封顶),**总尺寸可以逼近 `message_size_limit` 两个数量级于 hopcount 的语义边界**。
3. **空白伪装对 Postfix 无效;非 ASCII field-name 是另一个维度的问题**:空白变体会被规范化并照常计数;而非法非 ASCII field-name(未声明 SMTPUTF8 的裸 UTF-8 字节)不参与计数的同时,会触发 Postfix 3.7.11 的 header-termination 容错路径——头部区在其处终结,其后合法头被降级为正文(该行为已可通过 Postfix ≥3.11 的 `non_empty_end_of_header_action` 策略项显式控制,跨版本对照见 Phase 3A)。
4. 因此"无限制"的准确表述是:**计数维度在 49 条封顶,其余所有维度并行无界至 10MB**;且存在一个免费的头部致盲原语(畸形头名终结头部区),其危害大于单纯的数量增长。



## 7. 产物清单

| 文件 | 内容 |
| --- | --- |
| `results/phase2.csv` | 第二阶段 16 用例结果(Resent/折叠巨头/重复字段/同形名/ARC/边界控制) |
| `results/scan_limit50.csv` | N=0~100 主数据集(101 行) |
| `results/scan_limit8.csv` | limit=8 交叉验证(N=0~12) |
| `results/variants_*.csv` | X-Received / Received-SPF / 大小写变体 |
| `results/loop/LOOP01.*.log` | 真实循环三节点完整日志 + SMTP 会话记录 |
| `results/phase3/matrix.csv` | Phase 3A 差分矩阵(5 轮 × 12 用例,23 列结构化指标) |
| `results/phase3/corpus/` | V001~V012 字节固定输入 + `manifest.json`(逐文件 sha256) |
| `results/phase3/<ENV>/<POLICY>/<case>/` | 每事务全量证据:input.eml、输出 raw.eml/.sha256/.parsed.json、SMTP 日志、三节点日志、result.json |
| `freeze/`(仓库内,随 git 版本化) | PF37/PF11 环境冻结清单:postconf -n/-d 转储、镜像 digest、compose 快照 |
| `scripts/build_corpus.py` | 字节级确定性 corpus 生成器(固定日期,CRLF,X-Case-ID 置首) |
| `scripts/phase3.sh` | Phase 3A 矩阵跑批(策略切换、采证、matrix.csv 追加) |
| `results/logs/<case>.*.log` | 每个用例的 SMTP 会话、三节点日志增量、Mailpit 核查结果 |
| `results/baseline_raw.eml` | 基线邮件原始报文(4 条 Received 的顺序样本) |
| `scripts/send_received.py` | 预置头注入发送器(样式:line / resent / arc / folded;`--input-file` 字节直发 corpus) |
| `scripts/check_delivery.py` | Mailpit 投递核查 + Received 计数 + 清空 |
| `scripts/inspect_raw.py` | 按 X-Case-ID 定位报文,输出头/体分类计数、最大头字节数等结构取证 |
| `scripts/scan.sh` | 自动扫描器(CSV + 证据日志) |
| `scripts/phase2.sh` | 第二阶段固定 16 用例跑批(写 `results/phase2.csv`) |
| `scripts/loop_test.sh` | 循环实验(运行时改拓扑,自动恢复) |
| `../references/rfc5321.txt` / `rfc5322.txt` | 本报告引用条款的 RFC 原文(6.1 节) |

环境当前状态:hopcount_limit=50、relayhost 链恢复原状,与 compose 文件一致;唯一持久化改动是 `postfix/entrypoint.sh` 的 chroot DNS 修复与 `maillog_file=/dev/stdout`(均为实验必需,建议保留)。

## 8. 复现命令

```bash
cd received-lab
docker compose up -d --build          # 构建并启动(首次会拉镜像)
# 主扫描(约 3 分钟)
bash scripts/scan.sh results/scan_limit50.csv 0 49
bash scripts/scan.sh results/scan_limit50.csv 50 100
# 临时降 limit 做交叉验证(运行时生效,无需重建)
for h in postfix1 postfix2 postfix3; do docker exec $h postconf -e 'hopcount_limit = 8'; docker exec $h postfix reload; done
bash scripts/scan.sh results/scan_limit8.csv 0 12
for h in postfix1 postfix2 postfix3; do docker exec $h postconf -e 'hopcount_limit = 50'; docker exec $h postfix reload; done
# 变体与循环实验
bash scripts/scan.sh results/variants_xreceived.csv 100 100 'X-Received' XR
bash scripts/loop_test.sh
# 第二阶段:RFC 无界增长路径(Resent / 折叠巨头 / 重复字段 / 同形名 / ARC)
bash scripts/phase2.sh
```

## 9. Phase 3A:同一 corpus 在 Postfix 3.7.11 vs 3.11.6 上的差分

研究问题(prompt.md 指定):**Postfix 3.7.11 的 malformed-header 终结行为,在新版中是否仍存在?新策略能否改变它?**

方法:双链路拓扑与参数完全一致(仅版本不同);corpus V001~V012 **字节级固定**(sha256 见 `results/phase3/corpus/manifest.json`,发送端 `--input-file` 原样传输);矩阵 = {PF37}×{default} + {PF11}×{default, fix_quietly, add_header, reject},共 60 个事务,数据 `results/phase3/matrix.csv`(61 行 × 23 列),每用例留有 `input.eml / 输出raw / sha256 / parsed.json / 三节点日志 / result.json`。

### 9.1 核心结果矩阵(关键用例)

| case | 内容 | PF37 3.7.11 default | PF11 3.11.6 default/fix_quietly | PF11 add_header | PF11 reject |
| --- | --- | --- | --- | --- | --- |
| V001 | 正常邮件 | 投递 | 投递 | 投递 | 投递 |
| V002 | Received ×46 | 投递,exact=50 | 相同 | 相同 | 相同 |
| V003 | Received ×47 | **P3 拒(554 hopcount)+ DSN** | 相同 | 相同 | 相同 |
| V004 | rEcEiVeD ×46 | 投递,exact=4/**ci=50** | 相同(ci=50) | 相同 | 相同 |
| V005/V006 | `Received :`/Tab ×5 | 规范化+计数(exact=9) | 相同 | 相同 | 相同 |
| V007 | `Receíved:` ×1 | 投递,From/To/Subject 降为正文 | **行为相同** | 投递 + **MIME-Error ×1** | **P1 拒:`550 5.6.0 primary header was terminated with non-empty line`** |
| V008 | `Receíved:` ×50 | 同 V007 | 相同 | 投递 + MIME-Error | P1 拒 550 |
| V009 | 无冒号行 | 同 V007 | 相同 | 投递 + MIME-Error | P1 拒 550 |
| V010 | Subject ×51 | 投递 | 相同 | 相同 | 相同 |
| V011/V012 | 折叠 90KB/150KB | 投递;150KB **截断至 101700B** | **截断至 101700B(同一阈值)** | 相同 | 相同 |

### 9.2 结论

1. **兼容性默认被完整继承**:PF37(已 EOL)与 PF11.6 在 default 下 12/12 用例行为一致 —— malformed header 终结容错(`fix_quietly` 语义)是**有意的兼容性默认**,不是 3.7 的遗留缺陷;`fix_quietly` 显式设置与 default 完全等价(实测证实文档语义)。
2. **行为开关是版本门控的**:只有 ≥3.11 可选 `add_header`(投递但追加 `MIME-Error: message header was not terminated by empty line` 告知头,消息自带"被修复"证据)与 `reject`(第一跳 DATA 阶段 `550 5.6.0` 拒收,cleanup 日志以 `reject: mime-error ...: <offending 行原文>` 引用肇事行,取证性极强)。
3. **hopcount 语义零漂移**:V002/V003 的 49 条边界、V003 的 P3 拒绝 + DSN 路径、V004 的大小写不敏感计数(ci=50/exact=4)在全部 5 轮中分毫不差;`header_size_limit` 截断阈值(101700/102400B)也跨版本一致。
4. **策略正交性**:`non_empty_end_of_header_action=reject` 只影响 header-termination 类用例,不影响 hopcount/尺寸/重复字段类用例 —— 两个维度在 3.11 中由独立机制处理。
5. 对第二阶段 ET050 的最终定性:该现象是 Postfix 的**兼容性容错路径**,在当前稳定版中默认保留、可显式加固;研究价值在于跨版本策略演化与"transport view ≠ parser view",而非一个"漏洞"。

Phase 3B(Exim/OpenSMTPD 同 corpus)与 3C(Python/Go/Node/Rspamd 解析差分)按 prompt.md 顺序推进,本文不再展开。
