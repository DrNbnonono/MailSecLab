"""Shared evidence helpers. Status labels are the week-1 vocabulary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

STATUSES = (
    "pass",
    "fail",
    "none",
    "parse-error",
    "policy-reject",
    "temp-error",
    "timeout",
    "tool-error",
    "pending",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_bytes(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return sha256_bytes(data)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def perl_feed(raw: bytes) -> bytes:
    """Match verify_perl.pl: strip one trailing CR/LF per record, emit CRLF."""
    if raw == b"":
        return b""
    text = raw.decode("latin1")
    parts = []
    buf = ""
    for ch in text:
        buf += ch
        if ch == "\n":
            parts.append(buf)
            buf = ""
    if buf:
        parts.append(buf)
    fed = []
    for line in parts:
        if line.endswith("\r\n"):
            line = line[:-2]
        elif line.endswith("\n") or line.endswith("\r"):
            line = line[:-1]
        fed.append(line + "\r\n")
    return "".join(fed).encode("latin1")
