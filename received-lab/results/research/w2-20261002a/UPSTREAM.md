# 上游核查与 CVE-2026-100891 关系声明（2026-10-02）

## 核查结论

1. **CVE-2026-100891**（PUBLISHED 2026-09-28T00:15Z，CNA=VulDB，报告人 Weitong Li，CVSS v3.1 7.3 / v4.0 6.9，CWE-172）：OpenDMARC ≤1.4.2 的 `libopendmarc/opendmarc_policy.c: opendmarc_policy_query_dmarc`（"Internationalized Domain Name Handler"）不做 U-label→A-label 转换，导致 IDN 域的 DMARC 验证完全绕过。exploit 公开于 https://weitongli.com/share/opendmarc-ulabel-not-converted.html 。厂商被联系但未回应。
   - 权威核验：CVE Program API（cveawg.mitre.org/api/cve/CVE-2026-100891）返回 PUBLISHED 记录。
   - 同一研究员同日还报告 CVE-2026-101014（`opendmarc_util_cleanup` 越界读，含上游 patch commit b3b1da9）。
2. **原作者覆盖面**（exploit 原文，测试于 2026-07-28/30）：U-label 绕过（p=reject 与 p=quarantine）；拉丁/CJK/西里尔同形字；OpenDMARC vs rspamd 差分（含合法 IDN 邮件假阴性）；在原始 UTF-8 字节节点发布 _dmarc TXT 也无效（缺陷在归一化、先于 DNS 匹配）；根因锚定 RFC 7489 §6.6.1 ToASCII 缺失。
3. **上游状态**：OpenDMARC 1.4.2（2022）后无上游发布；上游未回应 CVE；发行版仍在主动打包（Fedora 1.4.2-33、Debian 1.4.2-5.1、Arch、Gentoo）——存量暴露持续且无修复时间表。
4. **二进制佐证（本实验室）**：`libopendmarc.so` 的 strings 无任何 idna/idn2/punycode/utf 痕迹；Debian 包 1.4.2-2+b1。

## 对本项目主张的影响

- **撤回**「发现新机制」的表述：U-label 绕过、评估器分裂（OpenDMARC vs rspamd）、合法 IDN 假阴性三个环节原作者已覆盖，且已 CVE 化。w2 实验（2026-10-02）为独立复现（原作者测试时间早约两个月）。
- **我们仍独有的增量**（原作者明确未测）：
  1. **rua 聚合报告空洞**：评估器自己的 HistoryFile 记录 U-label 事件 `pdomain`（原始 UTF-8）+ `rua -`，聚合报告按 pdomain→rua 分组，受害域报告永远不含这些事件（`rua/reference-aggregate.*`）——「监控不可见」首次有直接证据。
  2. **NFD/Unicode 规范形变体**（`nfd/`）：OpenDMARC 对 NFD 与 NFC 同样失败（原始字节 qname → none）；**rspamd 3.4 对 NFD 同样归一化成功并给出 DMARC_POLICY_REJECT（查询 `_dmarc.xn--mnchen-3ya`）**——NFD 不扩大 CVE 范围，阴性结果如实记录。
  3. **服务端消费面**：Dovecot ENVELOPE 原样返回 U-label/NFD 字节；A-label 字符串 SEARCH 搜不到 U-label 邮件；SEARCH any-instance 语义。
  4. **显示层**（`display/`，5 张截图）：Roundcube 与 SnappyMail 把 A-label/NFC/NFD 三种形态**全部显示为受害者的 Unicode 品牌**（SnappyMail 三封列表行完全相同；Roundcube 对 A-label 的 mailto 也反转换为 U-label）——「显示层归一化、策略层只认 ASCII」的完整对照。
  5. C 线（d=/s= qname 构造：尾点链内自分裂、重复 d= 身份绑定、FWS 四方分裂）与 CVE 无关，仍为本项目独立产出。
- **论文重定位**：从「新漏洞」转向「对刚披露缺陷在真实接收栈中的系统性影响面表征」——报告空洞、消费面盲区、显示层归一化 + 对维护版评估器的差分测量（含阴性对照 NFD）。NOVELTY_CLAIM.md 的 Chen 对照表仍然有效，但差异对象的最后一列须加上「CVE-2026-100891 已覆盖核心绕过」。

## 待办（披露相关）

- 向原作者/相关协调方补充我们的增量发现前，按 PLAN 第 7–8 周的披露纪律执行；当前不联系任何厂商。
