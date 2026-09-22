# MailSecLab 参考文献索引

本目录收录与 `Received:` Trace 字段增长、投递路径伪造、邮件转发、解析差异和 SMTP smuggling 相关的 RFC 与公开论文。

## 建议阅读顺序

### 1. 与 Received 路径直接相关

1. **Sanchez, Duan, Dong (2010), _Understanding Forgery Properties of Spam Delivery Paths_**  
   文件：[2010_ceas_sdp.pdf](./2010_ceas_sdp.pdf)  
   来源：https://www.cs.fsu.edu/~duan/publications/2010_ceas_sdp.pdf  
   关系：直接研究垃圾邮件中 `Received:` 投递路径的伪造程度；与本项目 H/I 系列的伪造链和来源认定最接近。

2. **Van Staden, Venter (2010), _Adding Digital Forensic Readiness to the Email Trace Header_**  
   文件：[45_Paper.pdf](./45_Paper.pdf)  
   DOI：10.1109/ISSA.2010.5588258  
   来源：https://digifors.cs.up.ac.za/issa/2010/Proceedings/Full/45_Paper.pdf  
   关系：提出给 Trace/Received 信息增加完整性和路径缺口检测能力；可作为“Received 为什么不能天然可信”的取证方向文献。

3. **Luo et al. (2025), _Characterizing the Networks Sending Enterprise Phishing Emails_**  
   文件：[2025_Luo_Characterizing_Enterprise_Phishing_Networks.pdf](./2025_Luo_Characterizing_Enterprise_Phishing_Networks.pdf)  
   会议：PAM 2025；预印本 DOI：10.48550/arXiv.2412.12403  
   来源：https://escholarship.org/content/qt7vx5w4wg/qt7vx5w4wg_noSplash_c5680f46855ebe5b225e67ada80068ed.pdf  
   关系：使用真实企业邮件的 `Received:` 链恢复投递基础设施，并专门讨论伪造路径及“从接收方可信边界向外寻找来源”的方法；是现有 H3/I2 实验最重要的现代对照文献。

### 2. 解释跨组件解析和认证差异

4. **Chen, Paxson, Jiang (2020), _Composition Kills: A Case Study of Email Sender Authentication_**  
   文件：[2020_Chen_Composition_Kills_Email_Sender_Authentication.pdf](./2020_Chen_Composition_Kills_Email_Sender_Authentication.pdf)  
   会议：USENIX Security 2020  
   来源：https://www.usenix.org/system/files/sec20-chen-jianjun.pdf  
   关系：说明不同邮件组件对身份、异常头部和认证结果理解不一致时，会产生组合漏洞；可作为 Postfix/Exim/OpenSMTPD 计数和规范化差异的理论与方法依据。

5. **Shen et al. (2021), _Weak Links in Authentication Chains: A Large-scale Analysis of Email Sender Spoofing Attacks_**  
   文件：[2021_Shen_Weak_Links_in_Authentication_Chains.pdf](./2021_Shen_Weak_Links_in_Authentication_Chains.pdf)  
   会议：USENIX Security 2021  
   来源：https://www.usenix.org/system/files/sec21-shen-kaiwen.pdf  
   关系：系统研究 SPF、DKIM、DMARC、ARC、邮件服务和客户端之间的认证链弱点；适合支撑 rspamd 来源认定、链一致性以及后续 DKIM/ARC 实验。

6. **Liu et al. (2023), _Forward Pass: On the Security Implications of Email Forwarding Mechanism and Policy_**  
   文件：[2023_Liu_Forward_Pass_Email_Forwarding.pdf](./2023_Liu_Forward_Pass_Email_Forwarding.pdf)  
   会议：IEEE EuroS&P 2023；预印本：arXiv:2302.07287  
   来源：https://arxiv.org/pdf/2302.07287  
   关系：研究实际邮件转发怎样破坏 SPF/DKIM/DMARC/ARC 的隐含假设；可用于设计“真实转发跳数、Received 增长和认证链变化”的组合实验。

### 3. 解释 SMTP 与 MIME 解析差异

7. **Wang et al. (2025), _Email Spoofing with SMTP Smuggling: How the Shared Email Infrastructures Magnify this Vulnerability_**  
   文件：[2025_Wang_Email_Spoofing_with_SMTP_Smuggling.pdf](./2025_Wang_Email_Spoofing_with_SMTP_Smuggling.pdf)  
   会议：USENIX Security 2025  
   来源：https://www.usenix.org/system/files/usenixsecurity25-wang-chuhan.pdf  
   关系：研究不同 MTA 对 SMTP DATA 结束标志解释不一致造成的走私问题；直接对应项目 I1，并提供更完整的 MTA/服务测量方法。

8. **Andarzian, Meyers, Poll (2025), _Email Smuggling with Differential Fuzzing of MIME Parsers_**  
   文件：[2025_Andarzian_Email_Smuggling_Differential_Fuzzing.pdf](./2025_Andarzian_Email_Smuggling_Differential_Fuzzing.pdf)  
   会议：IEEE Security and Privacy Workshops 2025；DOI：10.1109/SPW67851.2025.00007  
   来源：https://www.cs.ru.nl/~erikpoll/papers/mime2025.pdf  
   关系：用差分模糊测试寻找邮件服务器、过滤器和客户端之间的 MIME 解析差异；可直接借鉴到本项目 Python/Node/Go/rspamd 的 Header 差分测试。

## 标准文档

- [RFC 5321 — Simple Mail Transfer Protocol](./rfc5321.txt)：`Received:` 添加规则、禁止修改既有 Trace、环路检测和 SMTP 大小要求。
- [RFC 5322 — Internet Message Format](./rfc5322.txt)：头字段语法、998 字符行限制、folding、Trace 字段及其 `unlimited` 数量定义。

## 新增文件完整性

| 文件 | 页数 | SHA-256 |
|---|---:|---|
| `2020_Chen_Composition_Kills_Email_Sender_Authentication.pdf` | 18 | `4e1247a497896d1056779b2f4e9007521e8506991b436301d7cea99708c9ec47` |
| `2021_Shen_Weak_Links_in_Authentication_Chains.pdf` | 18 | `feda974b037fba820788fa7b767763618f73bbf65157f7cfadaf432d1b24e6f6` |
| `2023_Liu_Forward_Pass_Email_Forwarding.pdf` | 19 | `5ea3138f85a0a20dd8fed45363f03feb6a55a8617da57098b5ca41c3c8ecffc1` |
| `2025_Andarzian_Email_Smuggling_Differential_Fuzzing.pdf` | 12 | `f05a3f26eeea75314f7fbaad19f1437b71067ccfd3a5f27797691785065cea88` |
| `2025_Luo_Characterizing_Enterprise_Phishing_Networks.pdf` | 29 | `515c257ed6fdaa522018f0a12fb45c66da4439be82ec6c1b3ec84ae132473d61` |
| `2025_Wang_Email_Spoofing_with_SMTP_Smuggling.pdf` | 21 | `18aad4de586394651d4458db4663b1de44a4e363c393ae88e808be71db6b6a01` |

## 与后续实验的映射

| 项目实验方向 | 优先参考文献 |
|---|---|
| Received 能否增长、路径能否伪造 | Sanchez 2010；Luo 2025 |
| rspamd source IP 与可信链边界 | Sanchez 2010；Van Staden 2010；Luo 2025 |
| Postfix/Exim/OpenSMTPD 规范化差异 | Chen 2020；Andarzian 2025 |
| 自洽伪造 Received 链（I2） | Luo 2025；Shen 2021 |
| SMTP smuggling（I1） | Wang 2025 |
| DKIM/ARC 与多跳转发 | Shen 2021；Liu 2023 |
| 自动生成异常头部并做差分测试 | Andarzian 2025；Chen 2020 |
