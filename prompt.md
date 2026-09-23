我把你当前 `research/received-trace` 分支、`REPORT.md`、发送/检查脚本以及你附上的 RFC 5321/5322 对照看了一遍。你现在这套实验已经不再只是“搭 SMTP 链路”，而是完成了一轮相当完整的 **Postfix 3.7.x 单实现黑盒语义测量**：`Received` 临界点、跨节点退信、真实 loop、大小写/空白变体、超长折叠头、Resent、重复字段和 ARC-style 头都已经覆盖了。 仓库本身也已经有 `send_received.py / scan.sh / phase2.sh / inspect_raw.py / loop_test.sh` 这一套自动化框架，方向是对的。

但我建议你**现在不要继续在 Postfix 3.7 上机械增加“第 17、18、19 种怪头部”**。下一阶段最有研究价值的方向应该转成：

> **同一封边界邮件，在不同版本、不同 MTA、不同解析器和不同安全组件眼里，究竟是不是“同一封邮件”？**

这会把现在的工作从“Postfix 参数行为测试”升级成一个更完整的 **邮件传输链解析差异 / 信任边界研究**。

---

## 一、开始下一阶段之前，我建议先修正当前实验的几个问题

这里有几项我认为比较重要，尤其如果以后要拿这些数据写报告或论文。

### 1. 你的实验环境目前还没有真正“冻结”

Postfix Dockerfile 是：

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y postfix ...
```

没有锁定 Debian digest，也没有锁定 Postfix patch version；Mailpit 更直接用了 `axllent/mailpit:latest`。

所以你报告里的：

> Postfix 3.7.11

是“这一次运行时”的事实，却不是仓库未来重新 build 一定能得到的环境。

下一次实验前先保存：

```text
git commit
docker image inspect ...
postconf -d
postconf -n
postconf mail_version
docker compose config
```

并记录镜像 digest。之后最好做：

```text
postfix-3.7/
postfix-current/
```

两个显式版本环境。

这件事优先级很高，因为你马上就会做**版本差异实验**。

---

### 2. `phase2.csv` 当前有一个实际的字段错位问题

你的 CSV header 是：

```text
case_id,
description,
smtp_code,
postfix1_result,
postfix2_result,
postfix3_result,
delivered,
received_ci_in_final,
largest_header_bytes,
notes
```

一共 10 列。

但 `phase2.sh` 实际写入时把：

```bash
${delivered:-}-${rcv:--}
```

拼成了一列，因此实际输出只有 9 个字段。

而且变量叫：

```text
received_ci_in_final
```

但 `rcv` 实际来自：

```bash
RECEIVED_STRICT
```

这不是 case-insensitive count。

你报告里其实已经发现了第一阶段 `Received:` 精确字符串统计会漏掉 `rEcEiVeD:` 的问题。 所以这一点建议现在彻底修掉，不然后面做 parser differential 会很容易产生假结论。

最好统一输出：

```text
received_exact
received_ci
received_ws_normalized
received_in_body
```

---

### 3. 不要再用 Subject 作为“是否投递”的主要定位依据

`check_delivery.py` 是通过：

```python
find_message(f"[{case}]")
```

查 Mailpit Subject 的。

但是你的 ET050 恰恰证明：

```text
Subject:
From:
To:
Message-ID:
```

可能因为 header section 提前终止而全部掉进 body。

也就是说，越是重要的 malformed-header case，越可能让这个定位方法失效。

你现在 `X-Case-ID` 放在伪造块**之前**，这个设计反而非常好。

以后统一使用：

```text
X-Case-ID → raw message search
```

Subject 只作为业务字段测量对象，不再作为实验定位字段。

---

### 4. `inspect_raw.py` 下一阶段必须升级成 byte-level

现在：

```python
r.read().decode(errors="replace")
```

会把原始字节转成 Unicode，并在非法编码时进行 replacement。

第一、二阶段问题不大，但下一阶段如果研究：

```text
0x80
非法 UTF-8
不同字节序列
header/body parser differential
```

这个操作会破坏原始证据。

从下一阶段开始建议同时保存：

```text
CASE.raw.eml          原始 bytes
CASE.raw.sha256
CASE.parsed.json
```

所有边界位置最好都用 **byte offset**：

```text
header_end_offset
first_malformed_offset
subject_offset
body_offset
```

这样以后你可以非常有底气地说：

> 输入字节完全相同，但 A 解释为 header，B 解释为 body。

这个结果比“Postfix 收没收到”有研究价值多了。

---

### 5. ET050 的表述建议收紧

这里是目前报告里最值得继续研究，同时也最需要谨慎表述的地方。

RFC 5322 对 field-name 的定义仍然要求 printable US-ASCII 字符；你注入的：

```text
Receíved:
```

因此不是一个合法的普通 RFC 5322 header field name。

而你的 `send_received.py` 又直接：

```python
stuffed.encode()
```

发送 UTF-8 字节，却没有使用 SMTPUTF8 语义。 RFC 5321 本身也要求普通 SMTP header 使用 US-ASCII。

所以目前最好不要写成：

> “UTF-8 同形 Received 可以绕过 Postfix”

更严谨的是：

> **“非法非 ASCII field-name 触发了 Postfix 3.7.11 对 non-empty header termination 的容错路径，使其后的字段被重新解释为正文。”**

这反而更加准确。

而且这里出现了一个非常值得你马上研究的新信息：

**当前 Postfix 官方文档已经增加了 `non_empty_end_of_header_action`。**

现行文档给出了：

```text
fix_quietly
add_header
reject
```

三种行为，并说明 `fix_quietly` 是向旧版本兼容的行为。当前官方文档标注该控制项为较新 Postfix 版本提供的机制。([Postfix][1])

这意味着：

> 你 ET050 发现的现象非常适合作为一个**跨版本行为演化实验**，而不是继续包装成一个 Postfix 未知“漏洞”。

这会成为我建议你的第三阶段第一个实验。

---

### 6. 你现在的 ARC 实验只能证明“ARC-named headers 不参与 hopcount”，还不能证明 ARC 安全语义

当前 `--style arc` 只是自行生成：

```text
ARC-Authentication-Results
ARC-Message-Signature
ARC-Seal
```

并填入假的 `b=` / `bh=` 字符串。

所以 AF100 很好地证明：

> 300 个 ARC-style header 对 `hopcount_limit` 没有影响。

但暂时不要把它扩大成：

> “ARC 链可以这样无限增长”

因为真正 ARC 还有：

```text
i=
链连续性
AMS verification
AS verification
cv=
密钥
```

后面如果研究 ARC，就应该引入**真实 ARC signer/verifier**。

---

## 二、RFC 部分还有一个建议你修改的地方

你报告把 RFC 5321 §4.5.3.1.8 简化为：

> 中继 MUST NOT perform validation tests on message header fields

这句话确实出现在该节，但这一节的标题其实是 **Recipients Buffer**，其上下文是在解释为什么不能根据 message header 里出现的 recipient 数量去拒绝邮件。

所以针对：

```text
51 个 Subject
51 个 Message-ID
```

我建议不要写：

> RFC 5321 §4.5.3.1.8 要求这些重复字段必须被接受。

改成：

> RFC 5321 invokes the general principle that relay SMTP servers should not validate message headers in this context; experimentally, Postfix 3.7.11 also does not enforce RFC 5322 field multiplicity constraints during relay.

会严谨很多。

而 RFC 5322 的确规定 `Subject`、`Message-ID` 最大出现一次，而 `trace`、`resent-*`、`Comments`、`Keywords`、optional-field 等可以多次出现。

同样，你写：

> Postfix 50 低于 RFC 建议 100

是可以的，但关键词一定保留：

> **SHOULD normally at least 100**

不是 MUST。RFC 5321 §6.3 的确是这么表述的。 Postfix 当前官方配置文档仍然记录默认 `hopcount_limit = 50`。([Vdukhovni][2])

---

# 三、我建议你的后续研究路线

| 阶段       | 核心问题                                      |                               研究价值 |   优先级 |
| -------- | ----------------------------------------- | ---------------------------------: | ----: |
| Phase 3A | **同一 Postfix 不同版本是否解释相同？**                |                         找版本演化和兼容行为 | ★★★★★ |
| Phase 3B | **不同 MTA 是否具有相同 header/hop 语义？**          |     从 Postfix 个例升级为 SMTP ecosystem | ★★★★★ |
| Phase 3C | **不同邮件 parser 是否解释成同一结构？**                |         parser differential，非常有研究味 | ★★★★★ |
| Phase 4  | **伪造 Received 能否改变安全组件对 source hop 的认知？** |                        从协议现象进入安全后果 | ★★★★★ |
| Phase 5  | **DKIM/DMARC/ARC 遇到这些边界报文怎样表现？**          | authentication parser differential | ★★★★☆ |
| Phase 6  | **DSN/loop 的实际资源增长规律是什么？**                |                           定量分析放大效应 | ★★★☆☆ |

其中前三个我认为是你接下来最应该做的。

---

# 四、你现在就可以开始做的 Phase 3A：Postfix 跨版本实验

我建议你下一步**直接做这个**。

目标不是寻找更多 header 名，而是回答：

> **Postfix 3.7.11 的 malformed-header 行为，在新版 Postfix 中是否仍然存在？新的 policy 能否改变它？**

具体按下面顺序做：

1. **冻结现有环境。** 给当前环境记为 `PF37`，记录 `postconf -n`、`postconf -d`、Postfix 版本、Docker image digest 和当前 Git commit。再建立第二套 `PF_CURRENT`，使用当前稳定 Postfix。保持 `client → P1 → P2 → P3 → Mailpit` 拓扑、hostname、hopcount、message size 完全一样，只改变 Postfix version。

2. **建立固定 corpus，而不是临时修改脚本。** 第一轮只需要大约 12 个 case：

```text
V001  正常邮件
V002  Received ×46
V003  Received ×47
V004  rEcEiVeD ×46
V005  Received<SPACE>: ×5
V006  Received<TAB>: ×5
V007  Receíved: ×1
V008  Receíved: ×50
V009  无冒号的一行 BROKEN_HEADER
V010  Subject ×50
V011  folded Received 90KB
V012  folded Received 150KB
```

这里特别重要的是：

```text
V007 / V008 / V009
```

因为它们研究的是 **header termination parser**，不是 hopcount。

3. **在新版 Postfix 上分别运行 header termination policy。** 如果版本支持，就分别测试：

```text
non_empty_end_of_header_action = fix_quietly
non_empty_end_of_header_action = add_header
non_empty_end_of_header_action = reject
```

重点观察的不是只有 SMTP code，而是：

```text
From 是否仍为 header
To 是否仍为 header
Subject 是否仍为 header
Message-ID 是否仍为 header
X-Case-ID 是否仍为 header
非法行最终在哪里
是否增加 MIME-Error
最终 DATA 回复
```

如果得到类似：

```text
PF37             → accepted / remaining headers become body
PF-current fix   → accepted / same compatibility behavior
PF-current add   → accepted / MIME-Error generated
PF-current reject→ rejected
```

这就是一个非常完整的**版本演化故事**。当前 Postfix 官方文档已经明确描述 `header_size_limit`、`hopcount_limit` 和 malformed header termination 相关控制，因此你可以同时把黑盒实验和实现文档对应起来。([Postfix][3])

4. **把结果 CSV 改成结构性指标。** 我建议下一阶段不要再只有：

```text
delivered=yes/no
received_count=N
```

而改成：

```text
case_id
mta
version
policy
smtp_final_code
reject_node
raw_bytes
raw_sha256
header_section_bytes
header_end_offset
logical_header_count
received_exact
received_ci
from_in_header
to_in_header
subject_in_header
message_id_in_header
malformed_line_in_header
malformed_line_in_body
normalized
notes
```

这样你的数据以后可以直接画热力图。

5. **所有 raw message 原封不动保存。** 不再只保存 Mailpit 解析后的结果。对每个 case 保存：

```text
results/phase3/PF37/V007/input.eml
results/phase3/PF37/V007/output.eml
results/phase3/PF37/V007/p1.log
results/phase3/PF37/V007/p2.log
results/phase3/PF37/V007/p3.log
results/phase3/PF37/V007/result.json
```

然后：

```bash
sha256sum input.eml output.eml
```

把“输入是不是完全一致”变成可以证明的事实。

6. **先只比较 Postfix 版本，不要同时引入 Exim。** 如果现在一次换 Postfix、Exim、Rspamd、DKIM，变量会重新混在一起。先完成：

```text
PF37 × corpus
PF-current × corpus
PF-current × 3 policies
```

得到第一张 differential matrix。

7. **完成后再进入 Phase 3B：MTA differential。** 下一组我建议优先：

```text
Postfix
Exim
OpenSMTPD
```

三种就够。

仍然把**完全相同的 `.eml` bytes**打进去。

你真正要寻找的是：

```text
Postfix: header/body boundary = offset A
Exim:    header/body boundary = offset B
OpenSMTPD: reject
```

或者：

```text
Postfix counts Received :
Exim doesn't
```

这种结果。

只要出现一个可靠 differential，研究价值就明显比继续在 Postfix 上扫 100 种头名称更高。

---

## 五、Phase 3C 会是我认为最可能出“有意思结果”的部分：解析器差异

MTA 只是第一层。

同一封最终 `.eml` 再分别交给：

```text
Python email
Go net/mail
Node mailparser
Rspamd parser
Mailpit
```

不要问它们“邮件是否合法”，只记录它们实际解释出来的结构：

```text
header 数
Received 数
From
Subject
Message-ID
header/body boundary
第一个 Received
最后一个 Received
是否 parse error
```

例如理想结果可能长成：

| input                | Postfix   | Python         | Node          | Rspamd      |
| -------------------- | --------- | -------------- | ------------- | ----------- |
| malformed field line | 后续为 body  | 后续为 body       | 后续仍解析成 fields | reject/flag |
| duplicate Subject    | 保留 51     | 返回 first       | 返回 last       | 产生异常 symbol |
| Received + WSP colon | normalize | field name 含空格 | reject        | normalize   |

如果出现这种差异，你就得到了一个很清楚的研究核心：

> **Message interpretation is not a single property of the byte stream; it depends on the parser and trust boundary.**

这比单纯的：

> Postfix hopcount_limit 是 50

强很多。

---

# 六、然后再进入真正的“安全后果”：Received 信任边界

你报告里目前已经提出一个非常好的问题：

> 成功投递时可以携带大量预置 Received，那么下游如何知道哪些是真的？



这个问题不要靠推测，下一阶段直接实验。

给链路增加：

```text
Postfix3
   ↓
Rspamd
   ↓
Mailpit
```

然后全部继续用本地保留地址，比如：

```text
192.0.2.10
198.51.100.20
203.0.113.30
```

只做实验网络，不用公网真实主机。

构造：

```text
真实连接来源 = client.lab.test
伪 Received 1 = 192.0.2.10
伪 Received 2 = 198.51.100.20
真实 P1/P2/P3 Received
```

你不需要首先研究“能不能骗过垃圾邮件系统”。

先研究一个更基础、更干净的问题：

> **Rspamd 最终认定的 source IP / HELO / trusted relay boundary 是哪一跳？**

然后改变：

```text
trusted_networks
local_networks
```

再跑一次。

这样你就能回答：

> Received 虽然协议层不可认证，但安全组件是否通过 trusted relay boundary 自动丢弃不可信部分？

这才是你报告第五节中“若下游反垃圾依赖 Received 链分析”这一推测最好的实证续篇。

---

# 七、DKIM / DMARC / ARC 建议放在这个之后

不要现在立刻跳过去。

因为前面 parser differential 做清楚以后，DKIM 实验会自然产生很好的问题：

```text
MTA 认为某字段属于 body，
DKIM verifier 是否也这么认为？

两个解析器如何处理 duplicate Subject？

From 在 malformed boundary 后消失时，DMARC 怎么处理？

真实 ARC verifier 如何处理预置的 fake ARC set？

已有 ARC chain 经普通 relay 后是否保持？
```

这时再把你的 fake ARC generator 替换成：

```text
真实 ARC signer
真实 ARC verification
```

结果才真正能叫 ARC 实验。

---

## 我对你当前研究主题的重新归纳

你第一阶段实际上证明的是：

> **Hop count ≠ header complexity。**

你的第二阶段证明的是：

> **Postfix 的 loop-control view 与 message-header structure 是两个不同维度。**

而接下来最值得证明的是：

> **Transport view ≠ parser view ≠ security view。**

于是整个项目会形成非常漂亮的递进：

```text
Phase 1
Received 数量
        ↓
Postfix hopcount semantics

Phase 2
其他 header / malformed header
        ↓
hopcount 与 header complexity 解耦

Phase 3
不同 version / MTA / parser
        ↓
message interpretation differential

Phase 4
Rspamd / trusted relay
        ↓
trace trust differential

Phase 5
DKIM / DMARC / ARC
        ↓
authentication semantics differential
```

我认为这里面**最应该马上做的是 Phase 3A：Postfix 3.7 vs 当前版本 + `non_empty_end_of_header_action`**。它直接承接你现在最有意思的 ET050 结果，而且实验规模很小，大概十几个 case 就能得到非常清晰的一张表。完成这一步之后，再加 Exim/OpenSMTPD，同一套 corpus 原样跑过去。这样你下一阶段的研究就不会变成“继续堆 case”，而会开始形成一个真正明确的研究问题。

[1]: https://www.postfix.org/postconf.5.html?from=20423&from_column=20423&utm_source=chatgpt.com "Postfix Configuration Parameters"
[2]: https://vdukhovni.github.io/postfix/postconf.5.html?utm_source=chatgpt.com "Postfix Configuration Parameters"
[3]: https://www.postfix.org/postconf.5.html?utm_source=chatgpt.com "Postfix Configuration Parameters"
