# w6-20261003a：Gap 2 变换链差分（chainrun）——代码层与首轮语料

计划：`docs/superpowers/plans/2026-10-03-gap2-chainrun.md`（run-id `w6-*`，与 Gap 1 的 `w5-*` 并行协调规则见计划首部）。

## 已完成（2026-10-03 深夜会话，提交 20abcfc…5b904b5）

| 任务 | 产物 | 状态 |
| --- | --- | --- |
| 1 verdicts 判决向量层 | `research/lib/verdicts.py` + 测试 | ✅ 7/7；**sigprobe2 九格锚定回放逐格复现**（只读验证与 Gap 1 并行无干扰） |
| 2 chainseeds 种子注册表 | `research/lib/chainseeds.py` + 测试 | ✅ 23 种子四源统一；corpus_check 承认通道（repair/w1 语料正文 `Case:` 行显式放行） |
| 3 chainrun 链引擎 | `research/lib/chainrun.py` + `run.py` chain stage + 测试 | ✅ 25/25；有序对 9 + 单跳前缀臂 3 + 双终点两臂 + Gap1 活动门 + 增量检查点 |
| 4 chainflip 分析层 | `research/lib/chainflip.py` + 测试 | ✅ 组合专属 flip / 路径依赖 / 字节非交换 / 只读抽样复核 |
| 6 被动语料首轮 | `research/lib/corpus_scan.py` + `corpus/` 产物 | ✅ 首批数字见下 |

全套测试：`python3 -m pytest research/tests/ -q` → 51 passed + 5 failed（test_runtime 的 5 个失败为 w3 RECORD 已记录存量，与本批无关）。

## 首轮被动流行率（详见 `corpus/PREVALENCE.md`）

- **Nazario phishing3（2,279 封）：by≠from 链不自洽 99.96%** vs **Enron beck-s ham（1,977 封）：0%**——w1 i2 自洽检测法在真实语料上的首次量化，与 Sanchez 2010 量级一致（16 年来首次复测），且 ham 全自洽构成干净阴性对照。
- Enron ham 中 >998 字节头区行出现率 1.7%——FC150/G4 超长折叠轴在合法邮件中真实存在。
- 诚实边界：mbox 的 bare-LF 是存储伪影；ham 侧 zone_anomaly 47.6% 主要为转发内嵌头区块（扫描器下版需区分首行类头行与正文深处类头行）；Nazario 年代早于 obs/外域 AR 攻击面（零命中符合预期），现代档案（lore/W3C/IETF）待补。
- 源可用性：SpamAssassin publiccorpus 与 TREC2007 官方链路已死（MANIFEST 记录），Nazario/AUEB raw 可用。

## 待栈窗口（Gap 1 活跃中，持续让行）

执行前核对：`python3 -c "from research.lib.chainrun import gap1_recent_activity; print(gap1_recent_activity(30))"` 为空、或与 Gap 1 会话明确协调后。

```bash
# 1) 冒烟（~15 分钟）：3 种子 × {os-os, pf 单跳} × capture 臂
wsl bash -c "cd /mnt/e/MailSecLab/received-lab && python3 research/lib/chainrun.py \
  --run-id w6-20261003a --limit 3 --sequences os-os --arms capture --gap1-clear"
# 冒烟锚（不符先修仪器）：
#   - 控制信 v00 N=1 过 os-os：投递且 received_zone_total = 1+2 = 3
#   - s2 种子过 os-os capture：obs-colon=1 保留、dkimpy=parse-error（sigprobe2 锚）
#   - ad-hoc exim 与 w3 `exim` 容器行为一致性（v01 capture：obs 保留+计数）

# 2) 全矩阵（~2.5–3 小时，保活循环先起）：
wsl bash -c "cd /mnt/e/MailSecLab/received-lab && python3 research/lib/chainrun.py \
  --run-id w6-20261003a --gap1-clear"
# Gap 1 空闲时也可走 stage 入口（无 --gap1-clear 需求时）：
#   python3 research/run.py --stage chain --run-id w6-20261003a

# 3) 分析：chainflip 产出 candidates.json（flip/路径依赖/非交换 + 20% 只读复核）
wsl bash -c "cd /mnt/e/MailSecLab/received-lab && python3 research/lib/chainflip.py w6-20261003a"
```

排队的其余栈任务：任务 0（栈基线核对，含 msl-opendkim libc 构建确认）、任务 5（ARC：rspamd arc + OpenARC 源码构建——**唯一需独占窗口的手术**）、任务 7（repair exim 列，已并入链引擎单跳前缀臂——repair 11 探针是注册表种子，跑全矩阵时自动补齐）、任务 8/9（mlmmj/Return-Path，P2）。

## 已知局限（预埋）

- chainrun 对 w1-from-above-mutant 的 rspamd milter 判决记 not-collected（共享 Message-ID 无法按 case 区分臂，字节级 AR/ENVELOPE 照常收集）。
- verdicts 的 AR 聚合取头区第一条 AR；「哪条被采信」属 GAP3 trust 层，stamps 明细已保留。
- norelay 臂无投递语义，delivery/milter 叶为基线哨兵值（分析层已按此设计）。
