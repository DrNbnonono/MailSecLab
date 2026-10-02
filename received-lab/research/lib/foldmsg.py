"""Strictly folded X-Received messages for the G4 redo."""
from __future__ import annotations

WIDTH = 78
TARGET = 78000


def folded_xreceived(index: int, target: int = TARGET) -> str:
    token = f"from trace{index}.example by trace{index}.example; token {index}"
    first = f"X-Received: {token}"
    if len(first) > WIDTH:
        raise ValueError(f"first line is {len(first)} octets")
    lines = [first]
    while sum(len(line) for line in lines) < target:
        need = target - sum(len(line) for line in lines)
        take = min(WIDTH - 1, need)
        if take <= 0:
            break
        lines.append(" " + ("B" * take))
    return "\r\n".join(lines)


def build_g4(n: int, case: str, target: int = TARGET) -> bytes:
    fields = [folded_xreceived(i, target) for i in range(n)]
    headers = [
        f"X-Case-ID: {case}",
        *fields,
        "From: Alice <alice@lab.test>",
        "To: Bob <bob@lab.test>",
        f"Subject: {case}",
        f"Message-ID: <{case}@lab.test>",
        "Date: Thu, 01 Oct 2026 12:00:00 +0000",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=us-ascii",
    ]
    body = f"g4-body {case}\r\n"
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("ascii")


def count_xreceived(raw: bytes) -> int:
    if b"\r\n\r\n" in raw:
        header = raw.split(b"\r\n\r\n", 1)[0]
        lines = header.split(b"\r\n")
    elif b"\n\n" in raw:
        header = raw.split(b"\n\n", 1)[0]
        lines = header.split(b"\n")
    else:
        return -1
    count = 0
    for line in lines:
        if line.startswith(b" ") or line.startswith(b"\t"):
            continue
        if line.split(b":", 1)[0].lower() == b"x-received":
            count += 1
    return count


def inspect_message(raw: bytes, expect_n: int | None = None) -> dict:
    problems = []
    if b"\n" in raw.replace(b"\r\n", b""):
        problems.append("bare LF")
    if b"\r" in raw.replace(b"\r\n", b""):
        problems.append("bare CR")
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        problems.append("no header terminator")
        return {"ok": False, "problems": problems}
    if raw.find(b"\r\n\r\n", sep + 4) >= 0:
        problems.append("extra blank line in body is allowed; noted")
    header = raw[:sep].decode("ascii", "replace")
    lines = header.split("\r\n")
    if any(len(line) > 998 for line in lines):
        problems.append("line longer than 998")
    if any(len(line) > WIDTH for line in lines if line.startswith(" ") or line.startswith("X-Received:")):
        problems.append(f"folded line longer than {WIDTH}")
    fields = []
    current = None
    for line in lines:
        if line.startswith(" ") or line.startswith("\t"):
            if current is None:
                problems.append("continuation without a field")
                continue
            if not (line.startswith(" ") or line.startswith("\t")):
                problems.append("continuation is not WSP")
            current.append(line)
        else:
            if current is not None:
                fields.append(current)
            current = [line]
            if " :" in line.split(":", 1)[0]:
                problems.append(f"obs space before colon: {line[:40]}")
    if current is not None:
        fields.append(current)
    xcount = 0
    unfolded = []
    for field in fields:
        name = field[0].split(":", 1)[0]
        if name == "X-Received":
            xcount += 1
            logical = "".join(field)
            unfolded.append(len(logical))
            if len(logical) > 102400:
                problems.append("unfolded X-Received exceeds 102400")
    if expect_n is not None and xcount != expect_n:
        problems.append(f"X-Received count {xcount} != {expect_n}")
    joined = "\r\n".join(lines)
    if "From:" not in joined:
        problems.append("From missing")
    # The extra-blank note above is not a failure.
    hard = [p for p in problems if not p.startswith("extra blank")]
    return {
        "ok": not hard,
        "problems": hard,
        "notes": [p for p in problems if p not in hard],
        "bytes": len(raw),
        "header_bytes": sep,
        "x_received": xcount,
        "unfolded_lengths": unfolded,
        "max_line": max((len(line) for line in lines), default=0),
        "syntax": "modern-folded",
        "obs_received": False,
    }
