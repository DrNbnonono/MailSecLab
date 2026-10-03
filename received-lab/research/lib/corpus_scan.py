"""corpus_scan: 公开语料被动流行率扫描——「会翻判决的字节」在野出现率。

GAP2 P1#6 / GAP5 §八 P1#7 / GAP4 §五.7 共用模块。被动测量：只读语料，
不投递任何邮件（与「不出公网发信」约束的边界就在这里）。

特征清单（全部锚定实验室已确认的差分结论）：
  obs_received / eightbit_name / nocolon_received / case_received
      —— w3 diffrun 八形态（tracefacts 分类）
  dup_from / dup_authentication_results / dup_dkim_signature 等
      —— w1 causal 实例选择轴
  foreign_ar（多条 AR 并存）/ domain_literal_from —— w2 arsurv / void
  by_from_mismatch —— w1 i2 自洽性检测法（Luo 2025 的可控离线版）
  overlong_lines（>998 物理行）/ header_8bit_bytes / bare_lf_corpus
      —— 行长/编码轴

语料格式：.eml 目录与 mbox 文件（公共档案的主流格式，含 lore.kernel.org、
W3C/IETF 归档与 SpamAssassin/Nazario/CEAS 经典语料）。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.tracefacts import facts as trace_facts, split_zone

_FEATURES = (
    "obs_received", "eightbit_name", "nocolon_received", "case_received",
    "dup_from", "dup_authentication_results", "dup_dkim_signature",
    "dup_reply_to", "dup_subject",
    "foreign_ar", "domain_literal_from", "by_from_mismatch",
    "overlong_lines", "header_8bit_bytes", "bare_lf_corpus", "zone_anomaly",
)

_FIELDISH = re.compile(rb"^([!-9;-~]+):")
_AR_LINE = re.compile(rb"^Authentication-Results:\s*([^\s;]+)", re.IGNORECASE)
_DOMAIN_LITERAL_FROM = re.compile(rb"^From:.*@\[", re.IGNORECASE | re.MULTILINE)
_REC_FROM = re.compile(rb"from\s+([^\s(;]+)")
_REC_BY = re.compile(rb"by\s+([^\s;)]+)")


def _received_lines(zone_lines: list[bytes]) -> list[bytes]:
    """归并折行后的 Received 逻辑行。"""
    merged: list[bytes] = []
    for line in zone_lines:
        if line[:1] in (b" ", b"\t") and merged:
            merged[-1] += b" " + line.strip()
        else:
            merged.append(line)
    return [l for l in merged if re.match(rb"^received\b", l, re.IGNORECASE)]


def _field_counts(zone_lines: list[bytes]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in zone_lines:
        if line[:1] in (b" ", b"\t"):
            continue
        m = _FIELDISH.match(line)
        if m:
            name = m.group(1).decode("latin-1").lower()
            counts[name] = counts.get(name, 0) + 1
    return counts


def scan_message(raw: bytes) -> dict:
    """单封消息特征计数。语料只读；畸形消息照扫不抛（阴性照记原则）。"""
    zone_lines, _body, _off = split_zone(raw)
    f = trace_facts(raw)
    out = {k: 0 for k in _FEATURES}
    rec = f["received"]
    out["obs_received"] = rec.get("obs-colon", 0)
    out["eightbit_name"] = rec.get("eightbit-name", 0)
    out["nocolon_received"] = rec.get("no-colon", 0)
    out["case_received"] = rec.get("case", 0)
    out["bare_lf_corpus"] = 1 if raw.count(b"\n") != raw.count(b"\r\n") else 0
    out["zone_anomaly"] = 1 if (f["empty_zone_lines"] or f["body_headerish"]) else 0

    counts = _field_counts(zone_lines)
    out["dup_from"] = max(0, counts.get("from", 0) - 1)
    out["dup_authentication_results"] = max(0, counts.get("authentication-results", 0) - 1)
    out["dup_dkim_signature"] = max(0, counts.get("dkim-signature", 0) - 1)
    out["dup_reply_to"] = max(0, counts.get("reply-to", 0) - 1)
    out["dup_subject"] = max(0, counts.get("subject", 0) - 1)

    authserv_ids = {m.group(1).decode("latin-1", "replace").lower()
                    for l in zone_lines
                    for m in [_AR_LINE.match(l)] if m}
    out["foreign_ar"] = 1 if len(authserv_ids) > 1 else 0

    out["domain_literal_from"] = 1 if _DOMAIN_LITERAL_FROM.search(raw) else 0

    # by≠from 自洽性：上一条 Received 的 by-clause 应等于下一条的 from-clause
    rlines = _received_lines(zone_lines)
    for prev, nxt in zip(rlines, rlines[1:]):
        m_by = _REC_BY.search(prev)
        m_from = _REC_FROM.search(nxt)
        if m_by and m_from:
            by_host = m_by.group(1).decode("latin-1", "replace").lower().strip(".()")
            from_host = m_from.group(1).decode("latin-1", "replace").lower().strip(".()")
            # IP 字面量/括号内注释不参与（真实链常见形态，不算伪造信号）
            if by_host and from_host and not by_host.startswith("[") \
                    and not from_host.startswith("[") and by_host != from_host:
                out["by_from_mismatch"] += 1

    out["overlong_lines"] = sum(1 for l in zone_lines if len(l) > 998)
    out["header_8bit_bytes"] = 1 if any(b > 0x7F for l in zone_lines for b in l) else 0
    return out


def iter_mbox_messages(data: bytes):
    """mbox 切分（unix From 分隔行；正文中的 >From 转义不展开——
    分隔行启发式：行首 'From ' 且后随可解析时间戳）。"""
    lines = data.split(b"\n")
    current: list[bytes] = []
    for line in lines:
        if line.startswith(b"From ") and re.match(rb"^From \S+.*\w{3} \w{3}", line):
            if current:
                yield b"\n".join(current).rstrip(b"\n") + b"\n"
            current = []
        else:
            current.append(line)
    if current:
        yield b"\n".join(current).rstrip(b"\n") + b"\n"


def scan_corpus_dir(corpus_dir: Path) -> dict:
    """扫描一个语料目录（.eml 与 .mbox 混合），返回特征计数与出现率。"""
    corpus_dir = Path(corpus_dir)
    totals = {k: 0 for k in _FEATURES}
    messages = 0
    files = 0
    examples: dict[str, list[str]] = {}
    for path in sorted(corpus_dir.rglob("*")):
        if path.suffix.lower() not in (".eml", ".mbox", ".txt", "") or not path.is_file():
            continue
        files += 1
        data = path.read_bytes()
        chunks = (list(iter_mbox_messages(data)) if path.suffix.lower() != ".eml"
                  else [data])
        for idx, msg in enumerate(chunks):
            messages += 1
            feats = scan_message(msg)
            for k, v in feats.items():
                totals[k] += 1 if v else 0
                if v and len(examples.get(k, [])) < 3:
                    examples.setdefault(k, []).append(f"{path.name}#{idx}")
    rate = {k: (totals[k] / messages if messages else 0.0) for k in _FEATURES}
    return {"corpus": str(corpus_dir), "files": files, "messages": messages,
            "features": totals, "rate": rate, "examples": examples}


def main(corpus_dir: str, out_json: str | None = None) -> dict:
    report = scan_corpus_dir(Path(corpus_dir))
    out = Path(out_json) if out_json else Path(corpus_dir) / "prevalence.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"messages": report["messages"], "files": report["files"],
                      "rate": {k: round(v, 6) for k, v in report["rate"].items()
                               if v > 0}}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("corpus_dir")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    main(args.corpus_dir, args.out)
