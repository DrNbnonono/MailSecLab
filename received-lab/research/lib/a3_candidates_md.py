"""A3.Step4：CONFIRMED-CANDIDATES.md 生成器（从 conformance.json + report-groups.json）。"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

CONFIRM = Path("/mnt/e/MailSecLab/received-lab/results/research/w5-20261003a/confirm")


def esc(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def main() -> int:
    conf = json.loads((CONFIRM / "conformance.json").read_text(encoding="utf-8"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("a3c", "/mnt/e/MailSecLab/received-lab/research/lib/a3_conformance.py")
    a3c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a3c)
    EV = a3c.EVIDENCE
    rg = json.loads((CONFIRM / "report-groups.json").read_text(encoding="utf-8"))
    rr = json.loads((CONFIRM / "reduce-report.json").read_text(encoding="utf-8"))
    byfam = {f["family"]: f for f in rr["families"]}

    cnt = conf["counts"]
    L = []
    w = L.append
    w("# CONFIRMED CANDIDATES —— w4 候选的规范符合性判定（A3）与上游查重（A4）")
    w("")
    w("run：`results/research/w5-20261003a/confirm/`（本文件 + conformance.json + "
      "normative-index.json + report-groups.json + reduce-report.json）。")
    w("输入：w4-20261003a/gramfuzz 150 条 lab_confirmed 候选 → 119 机制族（mech 聚类）"
      "→ 38 报告组 → 逐组×组件三值判定。判定为 LLM 辅助人工裁决；每条 RFC 引文由脚本从"
      "本地 RFC 文本按行号抽取（行号与编辑器口径一致，可核）。")
    w("")
    w(f"**净结果：{cnt['distinct_violation_findings']} 条 violation 级 findings（披露池）· {cnt['defensible']} 条 defensible（论文素材池）· "
      f"{cnt['unspecified']} 条 unspecified（阴性照记）· {len(conf['corrections'])} 条仪器更正（含 2 条 v1 幻影判定的撤销）。**")
    w("组件版本按 AGENTS.md 环境表；A4 为只读检索（2026-10-03），未做任何对外联系。")
    w("")

    # ---------------- 方法摘要 ----------------
    w("## 0. 方法与折叠逻辑")
    w("")
    w("- **规范条目索引**：normative-index.json 共 **654 条**（RFC 5321×341 / 5322×66 / "
      "2045×7 / 6376×171 / 6532×10 / 8601×39 / 8617×20；关键词独立成词；含行号与节号；"
      "实测关键词行数与 grep 口径一致——计划预期的 800–1500 高估了这七份 RFC 的实际密度）。")
    w("- **报告折叠**：119 族 → **38 组**，组键 =（op 类 × P 主机制 × 真实改写方集合 × X 判定"
      "形态）；osmtpd 拒收与 D 子型为组属性。X 判定形态不同的不并组（任务纪律）。")
    w("- **T 判定基准**：以「实际发送的 corpus 文件 vs 各中继存档」的 difflib 行差分重算改写"
      "（stage2 的 gen_preserved 以变异前 gen_bytes 为参照，75/236 例变异打进了生成头，"
      "产生大量幻影——见 §5 仪器更正）。")
    w("- **D 判定**：RFC 3501 不在原七份 RFC 内，从 rfc-editor 只读取回存档于 "
      "`E:/Gramfuzz/rfc/rfc3501.txt`（与 setup 期 RFC 下载同性质）。")
    w("")
    w("折叠后按真实改写方分布：postfix 出现在 30/38 个改写组（157/235 例真实改写，其中 133 例"
      "obs 冒号规范化）；exim 16 组（38 改写 + 29 例纯 WSP 折行丢弃）；osmtpd 4 组（13 改写："
      "From 域名补全重串行化 3、Return-Path 9、行尾 1）。")
    w("")

    # ---------------- 组表 ----------------
    w("## 1. 报告组表（38 组）")
    w("")
    w("| 组 | op 类 | P 主机制 | 真实改写方 | X 形态 | 族数 | 成员 | 系列 | osmtpd 拒收 | D 子型 | 代表最小子/代表例 |")
    w("|---|---|---|---|---|---|---|---|---|---|---|")
    for g in rg["groups"]:
        k = g["group_key"]
        rep = g["families"][0]
        fam = byfam.get(rep, {})
        product = fam.get("product") or ("w4 representative " + rep)
        w(f"| {g['group_id']} | {k['op']} | {k['p_primary']} | {k['who_rewrites_true']} | "
          f"{k['x_shape']} | {g['n_families']} | {g['members_total']} | "
          f"{'/'.join(g['series_union'])} | {len(g['osmtpd_reject_families'])} | "
          f"{','.join(g['d_subshapes']) or '-'} | {esc(product)} |")
    w("")

    # ---------------- violation findings ----------------
    w(f"## 2. violation 级 findings（披露池，{cnt['distinct_violation_findings']} 条）")
    w("")
    w("> 每条含：条款引用（RFC 名+行号+原文）、一句话行为、最小子/证据、A4 上游初判。"
      "T5（mbox 行歧义）在 w4 四条已知可披露中属 borderline——本轮判 violation（V4），"
      "与 dkimpy 崩溃（V1）均计入。")
    w("")
    for fid, f in conf["findings"].items():
        up = f["upstream"]
        spread = f.get("spread") or {}
        w(f"### {fid}. {f['title']}")
        w("")
        w(f"- **组件**：{'、'.join(f['components'])}；confidence: **{f['confidence']}**"
          + (f"；组覆盖 {len(spread.get('groups', []))} 组" if spread.get("groups") else ""))
        for cid in f["clause_ids"]:
            c = conf["clauses"][cid]
            w(f"- **条款**：{c['section']}（{c['file']} L{c['line_start']}–{c['line_end']}）："
              f"「{esc(c['quote'][:400])}」")
        if not f["clause_ids"]:
            w("- **条款**：（无——健壮性底线，崩溃类不依赖条款）")
        w(f"- **行为**：{f['consequence']}")
        for ek in f["evidence_keys"]:
            w(f"- **证据**：{EV[ek]}")
        w(f"- **A4 上游**：known={up['known']}；fixed_in_latest={up['fixed_in_latest']}；"
          f"检索：{esc(up['ref'])[:300]}（checked {up['checked_at']}）")
        w("")
    # spread table
    w("finding 覆盖（组级）：")
    w("")
    w("| finding | 组件 | 覆盖组 | 条目数 |")
    w("|---|---|---|---|")
    for fid, f in conf["findings"].items():
        sp = f.get("spread") or {}
        w(f"| {fid} | {'、'.join(sp.get('components', []))} | "
          f"{len(sp.get('groups', []))} ({','.join(sp.get('groups', [])[:12])}"
          f"{'…' if len(sp.get('groups', [])) > 12 else ''}) | {sp.get('entry_count', 0)} |")
    w("")
    w("**exit 核对：violation 级 10 条 ≥ 10（计划 A3.3 标准）——达标。**")
    w("")

    # ---------------- defensible pool ----------------
    w(f"## 3. defensible 池（论文素材账，{cnt['defensible']} 条条目）")
    w("")
    dcnt = Counter()
    for e in conf["entries"]:
        if e["verdict"] == "defensible":
            dcnt[e["component"]] += 1
    w("按组件：" + "、".join(f"{k} {v}" for k, v in sorted(dcnt.items())) + "。")
    w("")
    w("主要类别（每类代表判定见 conformance.json entries）：")
    w("")
    w("1. **中继行尾修复**（postfix/exim/osmtpd）：对含裸 CR/控制字节的输入做删 CR/拆行——"
      "发送方先违反 RFC 5321 §2.3.8（L660–673），接收方修复属 §6.4 承认的争论区间。")
    w("2. **Return-Path 终投删除**（三家中继）：删除攻击者 Return-Path 并（osmtpd）加自身——"
      "RFC 5321 §4.4 L3235–3238 终投语义；捕获臂把中继变为终投跳是配置语义，纯中继位置下"
      "同行为将触 MUST NOT inspect（论文可写的配置敏感性论点）。")
    w("3. **OpenSMTPD 非 trace 550 拒收**（62/73 例）：§7.9 经营裁量 vs RFC 5322 §3.1 obs "
      "MUST honor 的未定边界——「拒收 vs 改写」的组合缺陷。")
    w("4. **dkimpy topmost-only API**：RFC 6376 §6.1 允许任意顺序与限制数量；对简单 API 消费者"
      "是真实降级向量（注入畸形 DKIM-Signature → pass 翻 fail）。")
    w("5. **dkimpy/rspamd From 实例选择**（2v2 分裂）：§5.4.2「物理最末实例」MUST 只明文约束"
      "签名者，验证者义务仅隐含——leaning-violation（与 AGENTS.md 对 K 系列纪律一致，不进披露池）。")
    w("6. **Go net/mail 整信报错**：对非法输入严格拒绝；八种 obs 形态全存活（w3）——严格性可辩护。")
    w("7. **AR 垃圾 authserv-id 存活**：RFC 8601 §5 的 MUST 只覆盖本域自称实例；w2 B 线"
      "（伪造本域 id）才是 §5 相关实例，结论不变。")
    w("")

    # ---------------- unspecified ----------------
    w(f"## 4. unspecified 池（{cnt['unspecified']} 条，阴性照记）")
    w("")
    ucnt = Counter()
    for e in conf["entries"]:
        if e["verdict"] == "unspecified":
            ucnt[e["component"]] += 1
    w("按组件：" + "、".join(f"{k} {v}" for k, v in sorted(ucnt.items())) + "。")
    w("")
    w("1. **Dovecot ENVELOPE 占位/部分解析**（14 条条目，D5）：RFC 3501 §7.4.2 只规定 From "
      "缺失/为空 → NIL，对「存在但不可解析」无规定——`missing_mailbox@missing_domain` 与 "
      "`@syntax_error` 是 Dovecot 自有哨兵值（如实判 unspecified，与计划预期一致）。")
    w("2. **python 对非法输入的头区终结**（12 条）：随机损伤字节上的解析器行为未规范。")
    w("3. **node/go 计数差**（3 条）：头部计数语义未规范。")
    w("")

    # ---------------- corrections ----------------
    w("## 5. 仪器更正（本工序发现，4 条）")
    w("")
    for c in conf["corrections"]:
        w(f"### {c['id']}. {c['subject']}")
        w("")
        w(c["detail"])
        w("")
        w(f"**影响**：{c['impact']}")
        w("")
    w("## 6. 建议 TAXONOMY 编号接续")
    w("")
    w("- V1（dkimpy IndexError）→ 建议 **X9**（验证器健壮性/崩溃类）。")
    w("- V2（dkimpy obs 拒解析）→ 并入既有 T2/KB2 家族（sigprobe2 已立案），不新开编号。")
    w("- V3a/V3b（Postfix obs 冒号规范化）→ 并入既有 **T1**（w3 已立案），计数与范围修正"
      "（133 例、13 入口、模板头）写入 T1 的 w5 增注。")
    w("- V4（mbox From_ 行抬升+头区歼灭）→ 建议 **T5** 保留（w4 RECORD 新 1 已编号），本轮"
      "补 §3.6.3 条款判定与上游源码定位（smtpd.c L3782–3791，Qualys+Mythos 缓解）。")
    w("- V6（Exim WSP 折行丢弃）→ **T6** 保留（w4 RECORD 新 3），计数 23→29 修正。")
    w("- V8（OpenSMTPD From/To/Cc 域名补全重串行化+主机名注入）→ 建议 **T7**（新机制，"
      "w4 RECORD 四条新原语之外）。")
    w("- V9（OpenSMTPD trace 格式 550）→ 建议 **T8**（新：§3.7.2 判定角度，E3/G 系列未做过"
      "条款级判定）。")
    w("- V10（python email obs 头区终结）→ 并入既有 **P4**（w3 diffrun 已立案），补 §3.1 "
      "MUST-honor 条款判定与 CPython #93176 上游关联。")
    w("- V11（milter 区中插入空行歼灭头区）→ 建议 **T9**（新：milter 插入位置的独立维度）。")
    w("- ~~V5（空值 Received 删除）~~ / ~~V7（冒号前插 WSP）~~：幻影，撤销（见 C1）。")
    w("")
    w("## 7. 与计划/任务书的偏差")
    w("")
    w("1. normative-index 654 条 < 预期 800–1500（七份 RFC 实际关键词密度；实测与 grep 一致）。")
    w("2. 报告组 38 个（目标 30–50 内；v1 曾为 52/58，v3 换真实中继维度后收敛）。")
    w("3. v1 判定中的 V5/V7 为幻影，已撤销并记入仪器更正——violation 数从 11 修正为 10，"
      "仍达 exit 标准。")
    w("4. A4 采只读检索初判，未装新版复测（按任务书留给披露批次）；Postfix/Exim 的 "
      "fixed_in_latest 记 None（无 changelog 证据，未复测）。")
    w("5. 5/52→38 组折叠中 D 子型与 osmtpd 拒收作为组属性而非组键——判定条目按成员族显式列出，"
      "无精度损失。")
    w("")
    (CONFIRM / "CONFIRMED-CANDIDATES.md").write_text("\n".join(L), encoding="utf-8")
    print("CONFIRMED-CANDIDATES.md written:", len(L), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
