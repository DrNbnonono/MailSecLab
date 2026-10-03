"""A3.Step3/Step4 v2（真中继版）：逐组三值判定 + CONFIRMED-CANDIDATES.md。

v1→v2 的更正（依据本会话的字节级重核，详见 conformance.json.corrections）：
- gen_preserved 的参照物是变异前 gen_bytes（75/236 例变异打进了生成头）——
  「空值 Received 删除」「exim/osmtpd 冒号前插 WSP」两个 v1 判定是幻影，撤销；
- 真实普查（corpus 输入 vs 存档 difflib）：postfix 157 例改写（133 obs 冒号
  规范化为主）、exim 38 改写+29 WSP 行丢弃、osmtpd 13 改写；
- perl/go 在「有效签名+畸形第二 DKIM-Signature 实例」上逐签名行为正确，
  记录值是适配器/分类器口径伪影；
- V5/V7 撤销；新增 V3a/V3b 拆分（§4.4 trace 与 §3.6.3 一般头分列）。
violation 判定共 10 条（V1/V2/V3a/V3b/V4/V6/V8/V9/V10/V11）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CONFIRM = Path("/mnt/e/MailSecLab/received-lab/results/research/w5-20261003a/confirm")
RFC_DIR = Path("/mnt/e/Gramfuzz/rfc")
W4 = Path("/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz")
CHECKED_AT = "2026-10-03"

CLAUSE_SPEC = [
    ("C-5321-3.6.3", "rfc5321.txt", 1524, 1529, "RFC 5321 §3.6.3"),
    ("C-5321-4.4-nodelete", "rfc5321.txt", 3178, 3182, "RFC 5321 §4.4"),
    ("C-5321-4.4-returnpath", "rfc5321.txt", 3235, 3238, "RFC 5321 §4.4"),
    ("C-5321-3.7.2-noreject", "rfc5321.txt", 1582, 1587, "RFC 5321 §3.7.2"),
    ("C-5321-7.9-discretion", "rfc5321.txt", 4357, 4360, "RFC 5321 §7.9"),
    ("C-5321-2.3.8-lines", "rfc5321.txt", 765, 779, "RFC 5321 §2.3.8"),
    ("C-5322-3.1-obshonor", "rfc5322.txt", 527, 534, "RFC 5322 §3.1"),
    ("C-5322-4.2-obsfws", "rfc5322.txt", 1809, 1817, "RFC 5322 §4.2"),
    ("C-5322-4.5.7-obsreceived", "rfc5322.txt", 2112, 2113, "RFC 5322 §4.5.7"),
    ("C-5322-4.5.8-obsoptional", "rfc5322.txt", 2115, 2117, "RFC 5322 §4.5.8"),
    ("C-6376-6.1-order", "rfc6376.txt", 2431, 2439, "RFC 6376 §6.1"),
    ("C-6376-6.1-nextsig", "rfc6376.txt", 2481, 2493, "RFC 6376 §6.1"),
    ("C-6376-6.1.1-permfail", "rfc6376.txt", 2501, 2510, "RFC 6376 §6.1.1"),
    ("C-6376-5.4.2-lastinstance", "rfc6376.txt", 2319, 2328, "RFC 6376 §5.4.2"),
    ("C-8601-5-delete", "rfc8601.txt", 1521, 1526, "RFC 8601 §5"),
    ("C-3501-7.4.2-envelope", "rfc3501.txt", 4332, 4341, "RFC 3501 §7.4.2"),
]


def extract_quote(rfc_file: str, start: int, end: int) -> str:
    lines = (RFC_DIR / rfc_file).read_text(encoding="utf-8", errors="replace").split("\n")
    return " ".join(s.strip() for s in lines[start - 1:end] if s.strip())


def build_clauses() -> dict:
    return {cid: {"section": sec, "file": f, "line_start": a, "line_end": b,
                  "quote": extract_quote(f, a, b)}
            for cid, f, a, b, sec in CLAUSE_SPEC}


EVIDENCE = {
    "T1-received": "对照实际输入（corpus/gf-received-guided.tab-colon-0038.eml 首行 `Received\\t:;\\t\\t\\t(G…`）：postfix 存档为 `Received:;…`——冒号前 WSP 被删；exim/osmtpd 逐字节保留。另一例 gf-obs-received-fresh-0001：`Received :(` → `Received:(`（exim/osmtpd 保留）",
    "T1-template": "真实普查：postfix 对模板头同样规范化——`To\\t:`/`Date :`/`Subject :`/`Message-ID\\t:`/`X-Case-ID :`/`From\\t:`（如 gf-received-guided.tab-colon-0010 的 To、gf-obs-received-guided.tab-colon-0230 的 Message-ID）。obs 冒号规范化共 133 例（13 入口全覆盖）",
    "T1-attrib": "归因 postfix 核心：E 系列在无 milter 的默认三跳栈（received-lab-postfix1，同样 3.7.11）上同样把 `Received :` 规范化后计数（AGENTS.md E3）——非 milter 伪影",
    "T5-lift": "输入 diff 复核（corpus/gf-obs-from-fresh-0002.eml）：首行 `From \\t:\"\\t  ` → 存档 `X-Mailbox-Line: From \\t:\"\\t  `（更名抬升）；其后 milter 头（AR/X-Spam）后插入空行——头区在此终结，输入其余行（含 DKIM-Signature 与全部身份头）逐字节保留但全部落入正文区。exim/osmtpd 路径无 X-Mailbox-Line、头区完整",
    "T5-source": "postfix master smtpd.c L3782-3791（本地取回 /tmp/smtpd.c）：`if (strncmp(start + strspn(start, \">\"), \"From \", 5) == 0) { out_record(out_stream, REC_TYPE_CONT, \"X-Mailbox-Line: \", 16); }`——带注释 `Qualys+Mythos: DOS in mbox line reading loop`（安全缓解为有意设计）；3.7.11 与 3.11.6 二进制均含该串（容器内核验）",
    "T6-wspdrop": "输入 diff 复核（corpus/gf-received-guided.tab-colon-0010.eml）：exim 存档删除输入的纯 WSP 折行 `' '`（difflib delete op）；同类 29 例（RECORD 新 3 的 T6，真实计数从 23 修正为 29）。被删行是 obs-FWS 合法字节（RFC 5322 §4.2）",
    "osmtpd-domainappend": "w4 relay/osmtpd/gf-from-guided.tab-colon-{0008,0174}.stored.raw：From 头值中 `()` → `(@opensmtpd.lab.test)`（把自身主机名注入消息内容）；0174 另有 ` \\t` → `\\xa0\\t`（0x20 变 0xA0，破坏折行首 WSP）；postfix/exim 逐字节保留",
    "osmtpd-source": "OpenSMTPD master smtp_session.c（本地取回）：L2633 对 To/Cc/From 的 RFC5322_HEADER_END 调 `header_domain_append_callback`（L458+，向无域地址追加 listener hostname）——From/To/Cc 头整体经此重串行化；机制为有意设计（提交场景域名补全），对任意端口生效",
    "osmtpd-550": "w4 relay/osmtpd/*.smtp.txt：73/236 例 `550 5.7.1 … not RFC 2822 compliant`；按入口 received=7/obs-received=4/from=6/obs-from=7/sender=5/reply-to=7/return-path=3/resent-from=4/authres=5/dkim-tags=5/arc-aar=6/arc-ams=7/arc-as=7——11 例 trace 头触发。master smtp_session.c L2850-2853 TX_ERROR_MALFORMED → 550（有意设计，仍在 master）",
    "milter-midzone": "输入 diff 复核（corpus/gf-received-byte.insert-1179.eml [postfix]）：`X-Spam: Yes` 与空行两行被插入在输入折行 Received 头的中间（difflib insert op @in[8:8]）——空行提前终结头区，其后折行续行沉入正文",
    "returnpath": "真实普查：三家中继都删除攻击者注入的 Return-Path 头（postfix 10/exim 11/osmtpd 9 例，如 gf-return-path-guided.tab-colon-0005 的 `Return-Path:<>`）；osmtpd 另加自身 `Return-Path: <alice@lab.test>`（终投语义）",
    "barecr-repair": "真实普查：postfix 删除裸 CR 合并行（25 例，如 gf-received-byte.delete-0317 `Date:…+0000\\rSubject` → `…+0000 Subject`）；exim 把裸 CR 拆成折行（如 gf-arc-aar-byte.flip-0042）；osmtpd 剥行尾裸 CR（gf-sender-byte.flip-0688）。输入本身违反 RFC 5321 §2.3.8（发送方先违规）",
    "py-zonedeath": "reduced/gf-sender-guided.tab-colon-0000.eml（271B 最小子）本地复验：`X-Case-ID\\t: …` 行之上 From/To/Date/Subject/Message-ID 保留为头，该行起全部沉入 payload；legacy 与 default 两种 policy 同形（CPython 3.13.12）",
    "dkimpy-crash": "reduced/gf-obs-from-fresh-0002-sign.eml（759B 最小子，首行 `\\t\\r\\n`）容器内复现：dkimpy 1.1.8 dkim/__init__.py:372 `headers[-1][1] += lines[i]+b\"\\r\\n\"` → IndexError: list index out of range（非 DKIMException，未被模块级 verify() 捕获）",
    "dkimpy-obs-reject": "reduced/gf-sign-anchor-kb2-sign.eml（KB2 锚最小子，`Received :\\r\\n` 注入于有效签名之上）：dkimpy=parse-error / perl+go+rspamd=pass；reduced/gf-obs-from-fresh-0000-sign.eml：`From\\t\\t\\t:` → dkimpy MessageFormatError \"Unexpected characters in RFC822 header\"（obs-optional 合法形态被拒）",
    "perl-2sig-correct": "容器内直跑 Mail::DKIM（sigdump2.pl，逐行 PRINT 与 harness 同口径）：reduced/gf-dkim-tags-guided.tab-colon-0006-sign.eml → sig[0]=invalid(unsupported algorithm)（畸形实例 PERMFAIL，正确）、sig[1]=pass（有效签名验过）——w4 RECORD「perl 拒解析整信」是适配器只报 $sigs[0] 的口径伪影",
    "go-2sig-correct": "w4 sign/gf-dkim-tags-guided.tab-colon-0001-sign 详录：go stderr 同时打印 \"Invalid signature for : dkim: incompatible signature version\" 与 \"Valid signature for lab.test\"——逐签名正确；记录值 go=fail 是分类器先匹配 invalid 的口径伪影",
    "ar-survival": "w4 relay/postfix/：15 个 authres 案例过 msl-auth-postfix 边界，13 个攻击者 AR 内容尾部原样存活；边界 milter 另加自身 AR（dmarc/spf）——注入 AR 的 authserv-id 为语法垃圾，不携带 mail.lab.test",
    "dovecot-env": "w4 imap/：D5 三形态——missing_mailbox@missing_domain（占位）、<垃圾>@syntax_error（部分解析）、多段 From 合并地址组（fresh-0000 的 7 元素组）；IMAP 消费者看到的发件人既非注入值也非模板值",
}

# ---------------- A4 上游查重结果（只读检索，2026-10-03） ----------------
UPSTREAM = {
    "V1": {"known": False, "fixed_in_latest": False,
           "ref": "https://bugs.launchpad.net/dkimpy（11 个 open bug 无一匹配；检索式 IndexError/rfc822_parse/obs/whitespace）；最新版 1.1.8（PyPI）=实验室版本，容器内复现崩溃",
           "checked_at": CHECKED_AT},
    "V2": {"known": False, "fixed_in_latest": False,
           "ref": "https://bugs.launchpad.net/dkimpy（同上，无 obs 解析拒绝相关 bug）；1.1.8 仍拒 obs 合法头",
           "checked_at": CHECKED_AT},
    "V3a": {"known": False, "fixed_in_latest": None,
            "ref": "postfix.org 无 GitHub tracker；announcements/RELEASE_NOTES/man 页（3.11.6 容器内 grep）无 obs 头规范化记载；3.11.6 未复测（留披露批次），无 changelog 修复迹象",
            "checked_at": CHECKED_AT},
    "V3b": {"known": False, "fixed_in_latest": None,
            "ref": "同 V3a；E3（默认无 milter 栈）证明非 milter 伪影",
            "checked_at": CHECKED_AT},
    "V4": {"known": True, "fixed_in_latest": False,
           "ref": "机制为有意安全缓解：master smtpd.c L3782-3791 注释 Qualys+Mythos（mbox 行读循环 DoS 修复）；3.7.11 与 3.11.6 二进制均含；但头区歼灭副作用无任何 announcement/man 页记载——副作用大概率未报告",
           "checked_at": CHECKED_AT},
    "V6": {"known": False, "fixed_in_latest": None,
           "ref": "Exim master ChangeLog（~9000 行，至 4.99.1）无 WSP 折行丢弃/头改写条目（检索式 whitespace/folding/header rewrite/Received）；bugs.exim.org 已退役、code.exim.org 检索接口不可达（记仪器缺口）；4.99.1 无修复迹象",
           "checked_at": CHECKED_AT},
    "V8": {"known": True, "fixed_in_latest": False,
           "ref": "机制为有意设计：OpenSMTPD master smtp_session.c header_domain_append_callback（L458+，L2633 调用）——From/To/Cc 域名补全重串行化；仍在 master。垃圾触发的自身主机名注入+0xA0 劣化副作用未见报告（openbsd/src 镜像无 issue tracker）",
           "checked_at": CHECKED_AT},
    "V9": {"known": True, "fixed_in_latest": False,
           "ref": "有意设计：master smtp_session.c L2850-2853 TX_ERROR_MALFORMED → 550 \"not RFC 2822 compliant\"，仍在 master；OpenBSD 官方 bug 走 bugs.openbsd.org/邮件列表（无 GitHub issue），检索受限",
           "checked_at": CHECKED_AT},
    "V10": {"known": True, "fixed_in_latest": False,
            "ref": "CPython #93176（gh-93158）“Support obsolete email syntax, fieldnames that are followed by whitespace”仍 open；关联 #76787/#158157（whitespace-padded 头名注入保护绕过，open）；3.13.12 实测行为仍在",
            "checked_at": CHECKED_AT},
    "V11": {"known": False, "fixed_in_latest": None,
            "ref": "无公开 tracker 条目（postfix 无 GitHub tracker；rspamd GitHub 未逐条检索——组件归属 postfix cleanup vs libmilter vs rspamd milter 未从字节面分离）；记 confidence: medium",
            "checked_at": CHECKED_AT},
}

FINDINGS = {
    "V1": {"title": "dkimpy 1.1.8：消息首行为 WSP 折行时 IndexError 崩溃（健壮性）",
           "components": ["dkimpy"], "clause_ids": [], "evidence_keys": ["dkimpy-crash"],
           "confidence": "high",
           "consequence": "攻击者以一封首行为单个 TAB 的信使 dkim.verify() 消费方崩溃/不可用；同信 perl/go/rspamd 均 pass——同一封信四种命运（T5 链的文件臂半边）"},
    "V2": {"title": "dkimpy 1.1.8：对 obs 合法头整信拒解析，有效签名不可验（RFC 5322 §3.1）",
           "components": ["dkimpy"],
           "clause_ids": ["C-5322-3.1-obshonor", "C-5322-4.5.7-obsreceived", "C-5322-4.5.8-obsoptional"],
           "evidence_keys": ["dkimpy-obs-reject"], "confidence": "medium",
           "consequence": "obs-received/obs-optional 合法形态（`Received :`、`From\\t\\t\\t:`）使带有效签名的信在 dkimpy 处 parse-error 而 perl/go/rspamd pass；Postfix 规范化后转 fail（T2/KB2 链）——验证分裂的最干净实例（w3 sigprobe2）"},
    "V3a": {"title": "Postfix 3.7.11：规范化既有 Received 行的 obs 冒号（`Received :`/`Received\\t:` → `Received:`）",
            "components": ["postfix"],
            "clause_ids": ["C-5321-4.4-nodelete", "C-5321-3.6.3"],
            "evidence_keys": ["T1-received", "T1-attrib"], "confidence": "high",
            "consequence": "MUST NOT change a Received: line 的直接字面违反——trace 完整性条款；w3 diffrun 已确立（T1），本轮 133 例 obs 冒号规范化中 obs-received 入口 23 例"},
    "V3b": {"title": "Postfix 3.7.11：规范化身份/模板头的 obs 冒号（`From\\t\\t\\t:`/`To\\t:`/`Date :`/`Subject :`/`Message-ID\\t:`/`X-Case-ID :` → 严格形态）",
            "components": ["postfix"],
            "clause_ids": ["C-5321-3.6.3"],
            "evidence_keys": ["T1-template", "T1-attrib"], "confidence": "high",
            "consequence": "T1 扩展到全部 13 入口与模板头（w4 RECORD 新 1 的字节级确认+计数修正）；对 h= 覆盖该头的 DKIM 签名是改写性破坏；副作用是把 dkimpy 的 obs 拒解析修复为可解析（sigprobe2 的修复实例）"},
    "V4": {"title": "Postfix 3.7.11：mbox From_ 形首行抬升为 X-Mailbox-Line 并以空行歼灭头区",
            "components": ["postfix"],
            "clause_ids": ["C-5321-3.6.3"],
            "evidence_keys": ["T5-lift", "T5-source"], "confidence": "high",
            "consequence": "一个字节类别（空格 vs TAB）翻转 Postfix 整个处理路径：DKIM-Signature 与全部身份头沉入正文→过 postfix 后 perl/go/rspamd=none、dkimpy=fail、Dovecot ENVELOPE 占位（w4 RECORD 新 1 全链）。上游为 Qualys/Mythos 安全缓解的有意设计，副作用未报告"},
    "V6": {"title": "Exim 4.96：丢弃头部纯 WSP 折行（obs-FWS 合法字节）",
           "components": ["exim"],
           "clause_ids": ["C-5321-3.6.3", "C-5322-4.2-obsfws"],
           "evidence_keys": ["T6-wspdrop"], "confidence": "high",
           "consequence": "obs-FWS 合法的折行字节被静默删除（w4 RECORD 新 3；真实计数 29 例，从 23 修正）；对 h= 覆盖该头的 DKIM 签名是改写性破坏；与 postfix/osmtpd 的逐字节保留形成中继差分"},
    "V8": {"title": "OpenSMTPD 6.8.0p2：From/To/Cc 头经域名补全重串行化——自身主机名注入 + 0x20→0xA0 字节劣化",
           "components": ["osmtpd"],
           "clause_ids": ["C-5321-3.6.3"],
           "evidence_keys": ["osmtpd-domainappend", "osmtpd-source"], "confidence": "high",
           "consequence": "中继把 listener 主机名注入消息头值并引入破坏折行的非法首字节；w4 RECORD 四条新原语之外的第五条机制（上游源码定位 header_domain_append_callback，任意端口生效）"},
    "V9": {"title": "OpenSMTPD 6.8.0p2：基于畸形 trace 头格式 550 拒收（RFC 5321 §3.7.2）",
           "components": ["osmtpd"],
           "clause_ids": ["C-5321-3.7.2-noreject"],
           "evidence_keys": ["osmtpd-550"], "confidence": "medium",
           "consequence": "11/73 例拒收由 received/obs-received 入口触发——「receiving systems MUST NOT reject mail based on the format of a trace header field」；confidence: medium 因条款位于网关一节，语境外推到普通接收方"},
    "V10": {"title": "python email：obs 冒号行终结头区，其下全部头沉入正文（RFC 5322 §3.1）",
            "components": ["python"],
            "clause_ids": ["C-5322-3.1-obshonor", "C-5322-4.5.8-obsoptional", "C-5322-4.5.7-obsreceived"],
            "evidence_keys": ["py-zonedeath"], "confidence": "high",
            "consequence": "obs 合法头之下的 From/Subject/DKIM-Signature 对 python 消费者不可见——P4 一般化到 13 入口（w3 diffrun→w4）；legacy 与 default 两 policy 同形；CPython #93176 仍 open"},
    "V11": {"title": "msl-auth-postfix 栈：milter 头以空行收尾插入在折行头中间，提前歼灭头区",
            "components": ["postfix"],
            "clause_ids": ["C-5321-3.6.3"],
            "evidence_keys": ["milter-midzone"], "confidence": "medium",
            "consequence": "`X-Spam: Yes`+空行插入在攻击者折行 Received 头中间——头区提前终结，后续折行续行沉入正文；组件归属（postfix cleanup vs libmilter vs rspamd milter）未从字节面分离，判给整栈并降 confidence"},
}

COMP = {
    "postfix": "Postfix 3.7.11（msl-auth-postfix；E3 证明 obs 规范化在无 milter 默认栈同样发生）",
    "exim": "Exim 4.96", "osmtpd": "OpenSMTPD 6.8.0p2",
    "python": "python email（CPython 3.13.12，legacy/default 两 policy 同形）",
    "go": "Go net/mail（parser-go 容器）", "node": "Node mailparser（parser-node 容器）",
    "dkimpy": "dkimpy 1.1.8（dkim.verify 简单 API）", "perl": "perl Mail::DKIM（msl-verifiers 容器）",
    "rspamd": "rspamd 3.4", "dovecot": "Dovecot 2.3.19",
    "stack": "msl-auth-postfix 边界栈（OpenDMARC/rspamd milter）",
}

TRACE_ENTRIES = {"received", "obs-received"}

CORRECTIONS = [
    {"id": "C1", "subject": "gen_preserved 参照物错误（幻影改写）",
     "detail": "stage2 的 gen_preserved 以变异前 gen_bytes 为参照——75/236 例变异打进生成头，导致 107 例幻影「改写」标记与 163 例漏标（原始计数含 milter 插入伪影）。真实普查（corpus 输入 vs 存档 difflib）：postfix 157 例真实改写 / exim 38 改写+29 WSP 行丢弃 / osmtpd 13 改写。v1 判定中的「空值 Received 删除+空行杀区」（V5）与「exim/osmtpd 冒号前插 WSP」（V7）均为幻影，撤销——两例实际逐字节保留。",
     "impact": "w4 RECORD §2 的 T 保留组合统计（23/18/24/49）不可再引用；T 判定以本文件真实普查为准"},
    {"id": "C2", "subject": "perl/go 验证器记录值是适配器口径伪影",
     "detail": "verify_perl.pl 只打印 $sigs[0]（最顶签名）结果；verify_one.py 的 classify_text 先匹配 \"invalid signature\"。容器内直跑库：Mail::DKIM 与 go-msgauth 在「有效签名+畸形第二 DKIM-Signature 实例」上逐签名行为正确（sig[1]=pass / \"Valid signature for lab.test\"）。",
     "impact": "w4 RECORD 新 2「perl 落单（拒解析整信）」的解读更正为适配器伪影；X7/X8 的四验证器分裂在库层面主要是 dkimpy 简单 API 的文档化 topmost-only 设计"},
    {"id": "C3", "subject": "签名臂与中继臂测试了不同字节",
     "detail": "签名臂注入的是 gen_bytes（变异前），中继臂发送的是 corpus 文件（变异后）——75 例两臂字节不同。",
     "impact": "X 判定仍然有效（测的是它们测的：纯生成头+有效签名）；跨臂对比（file vs @postfix）对这 75 例应谨慎"},
    {"id": "C4", "subject": "byte.insert-0116 的 (None,None,None) 是缺数据不是拒收",
     "detail": "该例（裸 LF）被 corpus_check 三目标一致拦截，relay 臂未执行。",
     "impact": "不得记为「三家拒收」"},
]


def main() -> int:
    clauses = build_clauses()
    rg = json.loads((CONFIRM / "report-groups.json").read_text(encoding="utf-8"))
    rr = json.loads((CONFIRM / "reduce-report.json").read_text(encoding="utf-8"))
    s2 = json.loads((W4 / "stage2.json").read_text(encoding="utf-8"))
    rows = s2["rows"] if isinstance(s2, dict) else s2
    bycase = {r["case"]: r for r in rows}

    entries = []

    def emit(group, component, verdict, confidence, behavior, clause_ids, evidence_keys,
             members_scope=None, notes="", findings=None):
        entries.append({
            "group": group["group_id"], "group_key": group["group_key"],
            "component": component, "component_full": COMP.get(component, component),
            "verdict": verdict, "confidence": confidence, "behavior": behavior,
            "clauses": [{"id": c, **clauses[c]} for c in clause_ids],
            "evidence": [EVIDENCE[k] for k in evidence_keys],
            "families": members_scope if members_scope is not None else group["families"],
            "n_families_scope": len(members_scope) if members_scope is not None else group["n_families"],
            "notes": notes, "findings": findings or [],
        })

    for g in rg["groups"]:
        k = g["group_key"]
        who = k["who_rewrites_true"]
        trace = bool(TRACE_ENTRIES & set(g["entries"]))
        op, pp, xs = k["op"], k["p_primary"], k["x_shape"]
        truth = g.get("relay_truth") or {}

        def mechs_of(target_key: str) -> set:
            full = {"p": "postfix", "e": "exim", "o": "osmtpd"}[target_key]
            s = set()
            for fam, tt in truth.items():
                m = (tt.get(full) or {}).get("mechanisms") or []
                s.update(m)
            return s

        # ---------- T 维度 ----------
        for target, comp in (("p", "postfix"), ("e", "exim"), ("o", "osmtpd")):
            if target not in who.split("+"):
                continue
            ms = mechs_of(target)
            if comp == "postfix":
                pf = []
                cl = ["C-5321-3.6.3"]
                if "obs-colon-normalize" in ms:
                    pf.append("V3a" if trace else "V3b")
                    if trace:
                        cl.append("C-5321-4.4-nodelete")
                if "mbox-lift" in ms or xs == "dkimpy-tool-error-drown":
                    pf.append("V4")
                if op == "damage" and "content-rewrite" in ms and not pf:
                    pf.append("V11")  # damage 类无 obs 冒号时的改写多为 milter 插入/行尾类
                mech_desc = "；".join(sorted(ms)) or "content-rewrite"
                if pf:
                    emit(g, "postfix", "violation", "high",
                         "改写中转消息既有头区字节（机制：" + mech_desc +
                         "）。obs 冒号规范化（§3.6.3/§4.4 无限定 MUST NOT）、mbox 抬升头区歼灭、"
                         "milter 区中插入均属违规；行尾修复与 Return-Path 类见 defensible 条目。",
                         cl, ["T1-received", "T1-template", "T5-lift", "milter-midzone"],
                         findings=pf)
                else:
                    emit(g, "postfix", "defensible", "medium",
                         "改写仅含 defensible 机制（机制：" + mech_desc + "）：行尾修复（发送方先违"
                         "§2.3.8）与 Return-Path 终投语义。",
                         ["C-5321-2.3.8-lines", "C-5321-4.4-returnpath"],
                         ["barecr-repair", "returnpath"])
            elif comp == "exim":
                pf = ["V6"] if "wsp-line-drop" in ms else []
                mech_desc = "；".join(sorted(ms)) or "content-rewrite"
                emit(g, "exim", "violation" if pf else "defensible",
                     "high" if pf else "medium",
                     "Exim 改写中转消息既有头区字节（机制：" + mech_desc + "）。"
                     "纯 WSP 折行丢弃（obs-FWS 合法字节）为 §3.6.3 违规；"
                     "裸 CR 拆行是对发送方 §2.3.8 违规的修复、Return-Path 删除属终投语义——defensible。",
                     ["C-5321-3.6.3", "C-5322-4.2-obsfws"] if pf else
                     ["C-5321-2.3.8-lines", "C-5321-4.4-returnpath"],
                     ["T6-wspdrop", "barecr-repair", "returnpath"],
                     findings=pf)
            else:
                pf = ["V8"] if "domain-append-reserialize" in ms else []
                mech_desc = "；".join(sorted(ms)) or "content-rewrite"
                emit(g, "osmtpd", "violation" if pf else "defensible",
                     "high" if pf else "medium",
                     "OpenSMTPD 改写中转消息既有头区字节（机制：" + mech_desc + "）。"
                     "From/To/Cc 域名补全重串行化（含自身主机名注入与 0xA0 劣化）为 §3.6.3 违规；"
                     "Return-Path 终投语义与行尾修复 defensible。",
                     ["C-5321-3.6.3"] if pf else ["C-5321-4.4-returnpath", "C-5321-2.3.8-lines"],
                     ["osmtpd-domainappend", "returnpath", "barecr-repair"],
                     findings=pf)

        # defensible 的行尾/Return-Path 机制条目（改写组里非违规部分，单列以可审计）
        for target, comp in (("p", "postfix"), ("e", "exim"), ("o", "osmtpd")):
            if target not in who.split("+"):
                continue
            ms = mechs_of(target)
            if ms & {"bare-CR/control-char-repair", "return-path-final-delivery"}:
                emit(g, comp, "defensible", "medium",
                     "组内含行尾修复（裸 CR 处理）与/或 Return-Path 删除：输入本身违反 RFC 5321 §2.3.8"
                     "（发送方先违规），接收方修复是 §6.4 承认的争论区间；Return-Path 删除+自加属 §4.4 "
                     "终投语义（捕获臂把中继变为终投跳）——纯中继位置下同行为将触 §4.4 的 MUST NOT inspect。",
                     ["C-5321-2.3.8-lines", "C-5321-4.4-returnpath"],
                     ["barecr-repair", "returnpath"])

        # ---------- osmtpd 550 ----------
        rej = g.get("osmtpd_reject_families") or []
        if rej:
            trace_rej = [f for f in rej if bycase.get(f, {}).get("entry") in TRACE_ENTRIES]
            if trace_rej:
                emit(g, "osmtpd", "violation", "medium",
                     "对含畸形 trace 头（received/obs-received 入口）的消息回 `550 5.7.1 not RFC 2822 "
                     "compliant` 拒收——基于 trace 头格式拒收。§3.7.2 的 MUST NOT 位于网关一节"
                     "（语境外推到普通接收方），confidence: medium。",
                     ["C-5321-3.7.2-noreject"], ["osmtpd-550"], members_scope=trace_rej,
                     findings=["V9"])
            nontrace = [f for f in rej if f not in trace_rej]
            if nontrace:
                emit(g, "osmtpd", "defensible", "medium",
                     "对含畸形身份/AR/DKIM 头（非 trace）的消息回 550 拒收。§7.9 给站点拒绝的"
                     "经营裁量；RFC 5322 §3.1 的 obs MUST honor 是否约束 MTA 投递决策规范未明——"
                     "拒收是防御性选择，postfix/exim（接受并改写）与 osmtpd（拒收）都可辩护。",
                     ["C-5321-7.9-discretion", "C-5322-3.1-obshonor"], ["osmtpd-550"],
                     members_scope=nontrace)

        # ---------- P 维度 ----------
        if pp == "py-zone-death":
            if op in ("obs-colon", "fresh"):
                emit(g, "python", "violation", "high",
                     "在首条 obs 冒号行（`Field\\t:`/`Field :`，obs-optional/obs-received 合法形态）"
                     "终结头区：该行与其后所有头沉入正文，From 可见性翻转、字段数最低。legacy 与 "
                     "default 两 policy 同形（本地复验）。",
                     ["C-5322-3.1-obshonor", "C-5322-4.5.8-obsoptional"]
                     + (["C-5322-4.5.7-obsreceived"] if trace else []),
                     ["py-zonedeath"], findings=["V10"])
            else:
                emit(g, "python", "unspecified", "high",
                     "在首条不合规行（随机字节/行级损伤）终结头区。输入本身非法，RFC 5322 未规定"
                     "解析器对非法输入的恢复义务——宽松但有损是合法设计点；差分本身是发现。",
                     [], ["py-zonedeath"])
        elif pp == "go-whole-error":
            emit(g, "go", "defensible", "high",
                 "Go net/mail 对整信报错（err-g 视图）。触发样本含非法字节；w3 diffrun 已证 Go 对"
                 "八种 obs 形态头区全存活。严格拒绝非法输入无规范障碍；后果是 Go 消费者整信不可用"
                 "而 python/node 部分可用。", [], [])
        elif pp == "node-zone-death":
            emit(g, "node", "unspecified", "high",
                 "Node mailparser 在特定损伤形态下字段数最低/Received 计 0（如空值 `Received:\\r\\n` "
                 "不计，gf-obs-received-fresh-0005）。RFC 未规定头部计数语义；差分是发现不是违规。",
                 [], [])
        elif pp == "go-zone-death":
            emit(g, "go", "unspecified", "high",
                 "Go net/mail 在特定损伤形态下字段数最低。非法输入上的解析器行为未规范。", [], [])
        elif pp == "from-flip-only":
            emit(g, "python", "unspecified", "high",
                 "From 可见性（from_in_headers）在三家间翻转而无字段数分歧——损伤字节上的解释差分，"
                 "规范未覆盖。", [], [])
        elif pp == "none":
            emit(g, "python", "unspecified", "medium",
                 "P 差分落在原始计数差（特征提取未归类的形态），无条款可判。", [], [])

        # ---------- X 维度 ----------
        if xs == "dkimpy-tool-error-drown":
            emit(g, "dkimpy", "violation", "high",
                 "对首行为 WSP 折行（最小子 759B，首行 `\\t\\r\\n`）的消息抛 IndexError 崩溃"
                 "（dkim/__init__.py:372）——健壮性底线违规，无需条款。文件级 perl/go/rspamd 均 "
                 "pass；postfix 路径的判定翻转由 V4（X-Mailbox-Line 抬升）解释。",
                 [], ["dkimpy-crash"], findings=["V1"])
        elif xs == "dkimpy-parse-error-drown":
            emit(g, "dkimpy", "violation", "medium",
                 "对含 obs 合法头且带有效签名的消息整信拒解析（MessageFormatError），有效签名不可验"
                 "——perl/go/rspamd 同字节均 pass。RFC 5322 §3.1 要求解释消息时 obs token MUST be "
                 "honored。postfix 规范化后 dkimpy 转 fail（T2/KB2 链）。",
                 ["C-5322-3.1-obshonor", "C-5322-4.5.7-obsreceived",
                  "C-5322-4.5.8-obsoptional"], ["dkimpy-obs-reject"], findings=["V2"])
        elif xs == "perl-solo-parse-error":
            emit(g, "perl", "defensible", "high",
                 "记录值 perl=parse-error 是适配器口径伪影：verify_perl.pl 只打印 $sigs[0]；容器内"
                 "直跑库显示 sig[0]=invalid（畸形实例 PERMFAIL，正确）且 sig[1]=pass。Mail::DKIM "
                 "行为符合 §6.1.1 与 §6.1。w4 RECORD「perl 拒解析整信」据此更正。",
                 ["C-6376-6.1.1-permfail", "C-6376-6.1-nextsig"], ["perl-2sig-correct"],
                 notes="instrumentation artifact, not library behavior")
            emit(g, "dkimpy", "defensible", "high",
                 "dkim.verify() 文档化只验最顶签名；畸形注入实例在最顶时返回 False。§6.1 允许任意"
                 "顺序与限制尝试数量。对简单 API 消费者是真实降级向量（注入畸形 DKIM-Signature 于"
                 "有效签名之上→pass 翻 fail），但规范上可辩护。",
                 ["C-6376-6.1-order", "C-6376-6.1-nextsig"], ["perl-2sig-correct"],
                 notes="topmost-only by documented design")
            emit(g, "go", "defensible", "high",
                 "go-msgauth 逐签名行为正确（stderr 同时打印 Invalid/Valid）；记录值 go=fail 是分类器"
                 "先匹配 \"invalid signature\" 的口径伪影。非违规。",
                 [], ["go-2sig-correct"], notes="classifier artifact")
        elif xs == "dkimpy-rspamd-fail":
            emit(g, "dkimpy", "defensible", "medium",
                 "攻击者在有效签名之上注入第二个 From 实例：dkimpy 对 h=from 哈希了顶部（攻击者）实例"
                 "而非签名时存在的底部实例→有效签名 fail（w1 causal）。§5.4.2 的「物理最末实例」MUST "
                 "只明文约束签名者；验证者义务经由语义一致隐含——可辩护但倾向违规（与 AGENTS.md 对 K "
                 "系列的纪律一致）。",
                 ["C-6376-5.4.2-lastinstance"], [], notes="leaning-violation")
            emit(g, "rspamd", "defensible", "medium",
                 "同 dkimpy：双 From 实例即 fail（w1 causal）——顶部实例选择。",
                 ["C-6376-5.4.2-lastinstance"], [], notes="leaning-violation")
            emit(g, "perl", "defensible", "high",
                 "perl（与 go）自底向上取实例（w1 causal）——有效签名 pass，符合 §5.4.2 签名者语义。"
                 "正向对照。", ["C-6376-5.4.2-lastinstance"], [])

        # ---------- D 维度 ----------
        if g.get("d_subshapes"):
            emit(g, "dovecot", "unspecified", "high",
                 "ENVELOPE 对不可解析 From 的占位/部分解析语义：" + "/".join(g["d_subshapes"]) +
                 "。RFC 3501 §7.4.2 只规定 From 缺失/为空时 ENVELOPE 成员为 NIL，对「存在但不可"
                 "解析」无规定——占位符是 Dovecot 自有哨兵值。如实判 unspecified（RFC 3501 全文已"
                 "取回本地存档，引文可核）。",
                 ["C-3501-7.4.2-envelope"], ["dovecot-env"])

        # ---------- AR 存活 ----------
        if "authres" in g["entries"]:
            emit(g, "stack", "defensible", "medium",
                 "攻击者注入的 Authentication-Results（语法垃圾 authserv-id）过 msl-auth-postfix "
                 "边界原样存活（15 例中 13 例）。§5 的 MUST 只覆盖携带本域 authserv-id 的自称实例——"
                 "本轮语料不携带 mail.lab.test，MUST 不触发。w2 B 线（伪造本域 id 存活）才是 §5 相关"
                 "实例，结论不因本轮语料而变。",
                 ["C-8601-5-delete"], ["ar-survival"])

    # -------------------------------------------------- 统计与落盘
    def count(v):
        return sum(1 for e in entries if e["verdict"] == v)

    spread = {}
    for e in entries:
        for f in e.get("findings") or []:
            d = spread.setdefault(f, {"groups": set(), "components": set(), "entry_count": 0})
            d["groups"].add(e["group"]); d["components"].add(e["component"])
            d["entry_count"] += 1
    for d in spread.values():
        d["groups"] = sorted(d["groups"]); d["components"] = sorted(d["components"])

    doc = {
        "run_w4": "w4-20261003a", "run_w5": "w5-20261003a",
        "method": {
            "folding": "119 mech 族 → 38 报告组（v3：op 类×P 主机制×真实改写方集合×X 判定形态；真实改写方按 corpus 输入 vs 存档 difflib 重算）",
            "judgment": "LLM 辅助逐组人工裁决；条款引文由脚本从本地 RFC 按行号抽取（禁手抄）",
            "t_basis": "T 判定基于 w4 representative 的真实中继行为（真普查）；15 族有 T-OK 最小子、66 族 P 最小化砍掉 T 触发（reduce-report t_drift 阴性）",
            "clause_extraction": "引文=本地 RFC 文件 line_start..line_end 原文（行连接，空白折叠）；RFC 3501 从 rfc-editor 只读取回存档 E:/Gramfuzz/rfc/rfc3501.txt",
            "upstream": "A4 只读检索（api.github.com / bugs.launchpad.net / gitlab / raw 源码 / PyPI），2026-10-03；未做任何对外联系",
        },
        "clauses": clauses,
        "corrections": CORRECTIONS,
        "counts": {
            "groups": len(rg["groups"]), "entries": len(entries),
            "violation": count("violation"), "defensible": count("defensible"),
            "unspecified": count("unspecified"),
            "distinct_violation_findings": len(FINDINGS),
        },
        "findings": {fid: {**f, "upstream": UPSTREAM[fid], "spread": spread.get(fid)}
                     for fid, f in FINDINGS.items()},
        "entries": entries,
    }
    (CONFIRM / "conformance.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("entries:", len(entries), "| violation:", count("violation"),
          "| defensible:", count("defensible"), "| unspecified:", count("unspecified"))
    print("distinct violation findings:", len(FINDINGS))
    by_comp = {}
    for e in entries:
        by_comp.setdefault(e["verdict"], {}).setdefault(e["component"], 0)
        by_comp[e["verdict"]][e["component"]] += 1
    for v in ("violation", "defensible", "unspecified"):
        print(f"  {v}: {by_comp.get(v, {})}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
