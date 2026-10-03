"""verdicts: 语义事实层——在一个观察点上对一份字节收集判决向量。

facts（tracefacts）管字节，本模块管语义：同一份 .eml 经过任何组件之后，
判决向量描述「每个语义角色对它说了什么」。差分 = 两个判决向量的差。

判决来源四层：
  file          文件级四验证器（causal.verify_file：dkimpy/perl/go + rspamc 文件扫描）
  ar            投递后字节上的 milter 盖章（OpenDKIM/OpenDMARC 的 Authentication-Results；
                unfold_ars 收编自 repair_matrix，原文件保持不动）
  milter_rspamd rspamd milter 会话判决（日志 grep——与 rspamc 文件扫描是两个 oracle）
  envelope      Dovecot IMAP ENVELOPE 首元素（信封 From 的服务端视图）

events 恒为空列表：GAP3 oracle 事件分类学的接口，本层不实现。
erased / laundered 不自动判定——diff_verdicts 的结果上人工标注。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib import tracefacts
from research.lib.causal import verify_file


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- file 层

def file_verdicts(evidence_path: str) -> dict:
    """四验证器文件级判定。evidence_path 必须是容器内 /evidence 路径。"""
    raw = verify_file(evidence_path)
    out = {}
    for tool in ("dkimpy", "perl", "go"):
        out[tool] = (raw.get(tool) or {}).get("status", "tool-error")
    out["rspamd_file"] = (raw.get("rspamd") or {}).get("status", "tool-error")
    return out


# ---------------------------------------------------------------- ar 层

def unfold_ars(raw: bytes) -> list[str]:
    """头区 AR 行展开（收编自 repair_matrix，行为一致）。"""
    lines = raw[:raw.find(b"\r\n\r\n")].split(b"\r\n")
    out: list[bytes] = []
    for line in lines:
        if line.startswith((b"\t", b" ")) and out:
            out[-1] += b" " + line.strip()
        else:
            out.append(line)
    return [l.decode("utf-8", "replace") for l in out if b"Authentication-Results" in l]


def _grab(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else "absent"


def ar_verdicts(raw: bytes) -> dict:
    """AR 盖章解析。多条 AR 时 flat 字段取头区顺序第一条（哪个 AR 被采信是
    trust 层的问题，不在这里裁决），逐条明细保留在 stamps 供后续分析。"""
    stamps = []
    for line in unfold_ars(raw):
        stamps.append({
            "dkim": _grab(r"\bdkim=(\w+)", line),
            "dmarc": _grab(r"\bdmarc=(\w+)", line),
            "spf": _grab(r"\bspf=(\w+)", line),
            "arc": _grab(r"\barc=(\w+)", line),
            "header_from": _grab(r"header\.from=([^\s;]+)", line),
            "header_d": _grab(r"header\.d=([^\s;]+)", line),
        })
    if stamps:
        out = dict(stamps[0])
    else:
        out = {"dkim": "absent", "dmarc": "absent", "spf": "absent",
               "arc": "absent", "header_from": "absent", "header_d": "absent"}
    out["ar_count"] = len(stamps)
    out["stamps"] = stamps
    return out


# ---------------------------------------------------------------- milter 层

def parse_milter_symbol(text: str) -> str | None:
    m = re.search(r"(DMARC_POLICY_[A-Z_]+|R_DKIM_[A-Z]+|ARC_[A-Z_]+)", text or "")
    return m.group(1) if m else None


def milter_rspamd(case_id: str, message_id: str | None = None) -> str:
    """rspamd milter 会话判决（日志 grep）。message_id 缺省为 <case_id@lab.test>。"""
    mid = message_id or f"<{case_id}@lab.test>"
    code, out, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                       f"grep 'id: {mid}' /var/log/rspamd/rspamd.log | grep write_log | tail -1"],
                      timeout=30)
    return parse_milter_symbol(out) or "absent"


# ---------------------------------------------------------------- envelope 层

_ENV_FROM = re.compile(r'\(\(\s*(?:"[^"]*"|NIL)\s+NIL\s+"([^"]+)"\s+"([^"]+)"')


def envelope_from(envelope_response: str) -> str | None:
    """从 IMAP ENVELOPE 响应提取第一个 From 地址（mailbox@host）。"""
    m = _ENV_FROM.search(envelope_response or "")
    return f"{m.group(1)}@{m.group(2)}" if m else None


IMAP_SCRIPT = r'''
import imaplib, json, sys
case, out_path = sys.argv[1], sys.argv[2]
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, data = m.search(None, "ALL")
ids = data[0].split()
out = {"found": False}
# 第一遍：按 X-Case-ID 头字段匹配（常规情形）
for item in reversed(ids):
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = (msg[0][1] or b"") if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(out_path, "wb").write(raw)
    typ, env = m.fetch(item, "(ENVELOPE)")
    out = {"found": True, "uid": item.decode(), "bytes": len(raw),
           "envelope": (env[0] or b"").decode("utf-8", "replace")}
    break
# 第二遍（回退）：头区可能已被终结、X-Case-ID 沉入正文——按原始字节匹配最近 30 封
if not out.get("found"):
    for item in reversed(ids[-30:]):
        typ, full = m.fetch(item, "(BODY.PEEK[])")
        raw = full[0][1] if full and full[0] else b""
        if case.encode() not in raw:
            continue
        open(out_path, "wb").write(raw)
        typ, env = m.fetch(item, "(ENVELOPE)")
        out = {"found": True, "uid": item.decode(), "bytes": len(raw),
               "envelope": (env[0] or b"").decode("utf-8", "replace"), "matched_in_body": True}
        break
m.logout()
print(json.dumps(out))
'''


def imap_fetch(case_id: str, out_container_path: str,
               host_path: Path, tries: int = 10, delay: float = 1.0) -> bytes | None:
    """从 Dovecot 取 X-Case-ID 匹配的原文到 host_path（含正文回退匹配）。"""
    for _ in range(tries):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                           case_id, out_container_path],
                          timeout=60, stdin=IMAP_SCRIPT.encode())
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            parsed = {}
        if parsed.get("found"):
            return host_path.read_bytes() if host_path.exists() else None
        time.sleep(delay)
    return None


def imap_envelope(case_id: str) -> dict:
    """取 ENVELOPE 并提取信封 From 首元素。找不到返回空 dict。"""
    code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                       case_id, "/dev/null"],
                      timeout=60, stdin=IMAP_SCRIPT.encode())
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError:
        return {}
    addr = envelope_from(parsed.get("envelope") or "")
    return {"from_first": addr, "uid": parsed.get("uid")} if addr else {}


# ---------------------------------------------------------------- 汇总

def collect(evidence_path: str, raw: bytes | None = None,
            case_id: str | None = None, with_env: bool = False,
            chain: dict | None = None) -> dict:
    """在单个观察点上收集判决向量（chain 字段由调用方 chainrun 填）。"""
    return {
        "bytes": tracefacts.facts(raw) if raw is not None else None,
        "dkim": file_verdicts(evidence_path),
        "ar": ar_verdicts(raw) if raw is not None else {},
        "milter_rspamd": milter_rspamd(case_id) if case_id else "not-collected",
        "envelope": imap_envelope(case_id) if (with_env and case_id) else {},
        "chain": chain or {},
        "events": [],
    }


_DIFF_SECTIONS = ("dkim", "ar", "envelope")
_ABSENT = (None, "absent", {})


def diff_verdicts(a: dict, b: dict) -> dict:
    """逐叶比较两个判决向量的语义字段。

    关系 ∈ persist（相等）/ created（absent → 值）/ break（值变化或消失）。
    bytes/chain/milter 不参与：字节差用 tracefacts 对比，链事实由 chainrun 记，
    milter 判决在未投递路径上天然缺失，混入会把仪器缺席当语义变化。
    erased / laundered 在此结果上人工标注（写入 notes 由分析层携带）。
    """
    out: dict[str, dict] = {}
    for section in _DIFF_SECTIONS:
        keys = set((a.get(section) or {})) | set((b.get(section) or {}))
        for key in keys:
            va = (a.get(section) or {}).get(key)
            vb = (b.get(section) or {}).get(key)
            if va == vb:
                rel = "persist"
            elif va in _ABSENT and vb not in _ABSENT:
                rel = "created"
            else:
                rel = "break"
            out[f"{section}.{key}"] = {"a": va, "b": vb, "relation": rel}
    return out
