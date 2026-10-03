"""Canonical trace facts: byte-level Received classification in one schema.

同一个 facts dict 描述任何组件对同一字节做了什么：MTA 捕获、parser 目标、
验证器输入。差分 = 两个 facts dict 的差，而不是两个脚本的差。

本模块只用标准库、单文件：同一份文件复制进 MailTrace 的 mailtrace-core，
Windows 工作台与 WSL 实验室共用一个分类器（文件头保留 provenance 注释）。

互斥分类，每条头区物理行归且只归一类：
  strict        `Received:` —— RFC 5322，冒号紧贴字段名
  obs-colon     `Received :` / `Received<TAB>:` —— obs 语法，冒号前 WSP
  case          `rEcEiVeD:` / `RECEIVED:` —— 大小写变体（合法字段名）
  cfws          `Received(Router):` / `Rece(c)ived:` —— 字段名内注释
  eightbit-name `Receíved:` —— 字段名内非 ASCII 字节
  no-colon      `Received from ...` —— 该行永远成不了头字段

优先级：eightbit-name > cfws > no-colon > obs-colon > case > strict
（大小写与 obs 同时出现时记 case；语料中没有该组合，出现时再分家）。
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Iterable

_WSP = b" \t"
_FIELDISH = re.compile(rb"^[!-9;-~]+:")
_RELAY_MARKERS = (
    b"by msl-auth-postfix", b"by auth-postfix", b"by exim", b"by opensmtpd",
    b"by msl-osloop", b"by msl-postfix",
)


def _strip_comments(head: bytes) -> bytes:
    out, depth = bytearray(), 0
    for b in head:
        if b == 0x28:  # (
            depth += 1
        elif b == 0x29:  # )
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(b)
    return bytes(out)


def _is_subsequence(small: bytes, big: bytes) -> bool:
    it = iter(big)
    return all(c in it for c in small)


def classify_received_line(line: bytes) -> str | None:
    """对头区的一条物理行分类；不属于 Received 家族返回 None。"""
    colon = line.find(b":")
    head = line[:colon] if colon >= 0 else line[:80]
    ascii_fold = bytes(b for b in head.lower() if 0x20 <= b < 0x7F)
    folded = _strip_comments(ascii_fold).strip()
    has8 = any(b > 0x7F for b in head)
    if not folded.startswith(b"received"):
        # 8-bit 变体（如 Receíved）的 ASCII 骨架剥掉非 ASCII 字节后缺字符
        # （receved），用子序列判定家族归属。
        if not (has8 and folded and _is_subsequence(folded, b"received")):
            return None
    if has8:
        return "eightbit-name"
    if colon < 0:
        return "no-colon"
    core = head.rstrip(_WSP)
    # 无冒号行的「第一个冒号」会落在时间戳里：冒号前的伪字段名若含内部
    # 空白，该行永远成不了头字段（no-colon），优先于 cfws 判定。
    if not core or any(c in _WSP for c in core):
        return "no-colon"
    if b"(" in core:
        return "cfws"
    if core == b"Received":
        return "strict" if head == core else "obs-colon"
    if core.lower() == b"received":
        return "case"
    return "no-colon"


def split_zone(raw: bytes) -> tuple[list[bytes], bytes, int]:
    """在第一个头/体分隔符处切开。CRLF 与 bare-LF 并存时先出现者胜。
    返回 (头区物理行, 正文, 正文起始偏移)。"""
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf >= 0 and (lf < 0 or crlf <= lf):
        return raw[:crlf].split(b"\r\n"), raw[crlf + 4:], crlf + 4
    if lf >= 0:
        return raw[:lf].split(b"\n"), raw[lf + 2:], lf + 2
    sep = b"\r\n" if b"\r\n" in raw else b"\n"
    return raw.split(sep), b"", len(raw)


def facts(raw: bytes, relay_markers: Iterable[bytes] = ()) -> dict:
    """对一个观察点（输入语料或任一组件的输出字节）提取规范事实。"""
    zone_lines, body, zone_end = split_zone(raw)
    counts: Counter[str] = Counter()
    for line in zone_lines:
        if not line or line[:1] in _WSP:
            continue  # 折行 continuation 归属父行
        cls = classify_received_line(line)
        if cls is not None:
            counts[cls] += 1
    markers = tuple(relay_markers) or _RELAY_MARKERS
    body_lines = re.split(rb"\r\n|\n", body)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "total_bytes": len(raw),
        "zone_end": zone_end,
        "body_bytes": len(raw) - zone_end,
        "received": dict(counts),
        "received_zone_total": sum(counts.values()),
        "case_noncanonical": counts["case"],
        "relay_added": sum(1 for l in zone_lines if any(m in l for m in markers)),
        "no_colon_body": sum(1 for l in body_lines if classify_received_line(l) == "no-colon"),
        "body_headerish": sum(1 for l in body_lines[:50] if _FIELDISH.match(l)),
        "empty_zone_lines": sum(1 for l in zone_lines if not l),
    }


def corpus_check(raw: bytes) -> list[str]:
    """发送前结构自检（F1 教训的固化）。返回问题列表；空列表 = 干净。
    有意构造的 sink 语料会被标记——这是特性：预期中的问题必须显式承认。"""
    problems = []
    f = facts(raw)
    if f["empty_zone_lines"]:
        problems.append(f"{f['empty_zone_lines']} empty line(s) inside the header zone (double separator?)")
    if f["body_headerish"]:
        problems.append(f"{f['body_headerish']} header-like line(s) in the body (early zone end or sink)")
    if raw.count(b"\n") != raw.count(b"\r\n"):
        problems.append("bare LF present in a CRLF corpus")
    if f["zone_end"] >= len(raw):
        problems.append("no header/body separator found")
    return problems
