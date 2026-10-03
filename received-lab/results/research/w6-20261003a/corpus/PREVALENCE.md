# 首轮被动流行率（PREVALENCE，2026-10-03）

扫描器：`research/lib/corpus_scan.py`（十六特征，锚定 w1–w4 已确认差分）。
语料与消息数见同目录 `MANIFEST.md`。这是首轮 bootstrap（一封钓鱼语料 + 一位 Enron 用户的 ham），
结论只按「该语料内出现率」表述，不外推到全网。

## 数字

| 特征 | Nazario phishing3（2,279 封） | Enron beck-s ham（1,977 封） | 实验室对应结论 |
| --- | --- | --- | --- |
| by_from_mismatch（Received 链自洽性，i2 检测法） | **99.96%** | **0%** | w1 i2：自洽伪造链文件扫描可主导 rspamd source；本检测法在真实语料上的首次量化——钓鱼语料几乎全部链不自洽，合法 ham 全自洽（干净阴性对照） |
| zone_anomaly（正文类头行/头区异常行） | 72.7% | 47.6% | w3 diffrun v03/v04 沉正文轴；注意含转发内嵌头区的存储伪影（见注意事项） |
| header_8bit_bytes（头区非 ASCII 字节） | 1.7% | 0% | w2 A 线 EAI/8-bit 轴的野生存在证据 |
| overlong_lines（>998 字节头区物理行） | 0% | **1.7%** | FC150/G4 折叠轴：超长行在合法邮件中真实存在 |
| nocolon_received | 0.09% | 0% | w3 diffrun v03（无冒号行三 MTA 三种命运） |
| dup_reply_to | 0.09% | 0% | w2 replyto 实例选择轴 |
| obs_received / eightbit_name / dup_from / foreign_ar / domain_literal_from | 0 | 0 | 本轮语料未命中（年代早于这些攻击面的流行；现代档案待补） |

## 注意事项（测量伪影，诚实记录）

- `bare_lf_corpus=100%/97.8%` 是 **mbox 存储格式伪影**（mbox 以 LF 存储），不代表线上传输形态，不作为特征引用。
- `zone_anomaly` 在 ham 侧偏高（47.6%）主要来自**转发邮件正文内嵌头区块**（Enron 邮件正文常含完整转发头），与头区真终结（v03/v04 现象）不同源。下一版扫描器应区分「正文首行即类头行」与「正文深处出现类头行」。
- by_from_mismatch 的判定排除了 IP 字面量与括号内注释（真实链常见形态）；99.96% 与 Sanchez 2010（CEAS）在垃圾语料上的伪造率量级一致，为其后 16 年的首次复测。
- Nazario 年代 2004–2007：obs/外域 AR/重复 From 零命中符合预期（攻击面年代晚于语料），现代档案（lore/W3C/IETF）是下一步的关键。

## 复现

```bash
wsl bash -c "cd /mnt/e/MailSecLab/received-lab && \
  python3 research/lib/corpus_scan.py corpus/nazario --out /tmp/nazario.json && \
  python3 research/lib/corpus_scan.py corpus/enron-raw-ham --out /tmp/enron.json"
```
