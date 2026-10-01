import base64
import hashlib
import re

from ..models.report import HeaderField, SourceInfo

_LINES = re.compile(rb"[^\r\n]*(?:\r\n|\r|\n|$)")
_NAME = re.compile(rb"[\x21-\x39\x3b-\x7e]+\Z")


def unfold(value: str) -> str:
    return re.sub(r"(?:\r\n|\r|\n)(?=[ \t])", "", value).strip(" \t\r\n")


def scan(raw: bytes, input_kind: str) -> tuple[SourceInfo, list[HeaderField]]:
    """Locate physical header evidence; do not claim RFC semantic validity."""
    spans = []
    end = len(raw)
    separator = False
    line_number = 0
    for match in _LINES.finditer(raw):
        if match.start() == match.end():
            break
        line_number += 1
        line = match.group().rstrip(b"\r\n")
        if not line:
            end, separator = match.start(), True
            break
        if line.startswith((b" ", b"\t")) and spans:
            spans[-1][1] = match.end()
            spans[-1][3] = line_number
        else:
            spans.append([match.start(), match.end(), line_number, line_number])
    block = raw[:end]
    headers = []
    for number, (start, stop, first, last) in enumerate(spans, 1):
        data = raw[start:stop]
        first_line = data.splitlines()[0]
        name_bytes, colon, _ = first_line.partition(b":")
        trimmed = name_bytes.rstrip(b" \t")
        name = trimmed.decode("ascii") if colon and _NAME.fullmatch(trimmed) else None
        syntax = "standard" if name and name_bytes == trimmed else "obsolete" if name else "malformed"
        text = data.decode("utf-8", "replace")
        headers.append(HeaderField(
            id=f"header-{number:03}", name=name, raw=text,
            value=unfold(text.partition(":")[2]) if name else None,
            syntax=syntax, start_byte=start, end_byte=stop, start_line=first, end_line=last,
        ))
    return SourceInfo(
        input_kind=input_kind, input_sha256=hashlib.sha256(raw).hexdigest(), input_size_bytes=len(raw),
        header_sha256=hashlib.sha256(block).hexdigest(), header_size_bytes=len(block),
        header_base64=base64.b64encode(block).decode("ascii"), has_body_separator=separator,
        semantic_boundary_byte=0,
    ), headers
