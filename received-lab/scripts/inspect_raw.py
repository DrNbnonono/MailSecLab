#!/usr/bin/env python3
"""Byte-level structural analysis of a lab message.

Locates the message in Mailpit by its X-Case-ID header (searching stored raw
bytes), or analyses a local file via --file. Every boundary decision is made on
raw bytes; decoded text is only ever used for display.

Header/body boundary: first CRLFCRLF. A logical header may fold across
continuation lines (leading SP/TAB). A field-name is valid per RFC 5322 only
if it is non-empty printable US-ASCII (33..126 except ':') with no WSP before
the colon. Malformed names (e.g. "Received :", UTF-8 look-alikes, missing
colon) are what the header-termination experiments study.

Printed metrics (KEY: value):
  RAW_SHA256 RAW_BYTES
  HEADER_SECTION_BYTES HEADER_END_OFFSET BODY_OFFSET
  FIRST_MALFORMED_OFFSET      (absolute byte offset, empty if none)
  LOGICAL_HEADERS
  RECEIVED_EXACT              (body lines starting "Received:")
  RECEIVED_CI                 (logical headers whose field-name == received, any case)
  RECEIVED_SPACE              (lines starting "Received :")
  RECEIVED_UTF8               (lines starting b"Rece\xc3\xadved:")
  RECEIVED_IN_BODY            (all received-like lines demoted into the body)
  MALFORMED_IN_HEADER
  LARGEST_HEADER_BYTES
  NAME <n>: header=K body=B   (repeatable --name; header = field-name match,
                               body = case-insensitive line prefix match)

--save DIR additionally writes <CASE>.raw.eml, <CASE>.raw.sha256 and
<CASE>.parsed.json with all metrics.
"""
import argparse
import hashlib
import json
import sys
import time
import urllib.request

MP = "http://mailpit:8025"
CRLF = b"\r\n"
SEPARATOR = b"\r\n\r\n"
VALID_NAME_CHARS = set(range(33, 127)) - {ord(b":")}


def http_bytes(path):
    with urllib.request.urlopen(MP + path, timeout=8) as r:
        return r.read()


def get_json(path):
    return json.loads(http_bytes(path).decode())


def find_raw_by_case(case, limit=80):
    """Return stored raw bytes of the newest message whose header section
    contains 'X-Case-ID: <case>', or None."""
    marker = b"X-Case-ID: " + case.encode()
    for m in get_json(f"/api/v1/messages?limit={limit}").get("messages", []):
        raw = http_bytes(f"/api/v1/message/{m['ID']}/raw")
        if marker in raw.split(SEPARATOR, 1)[0]:
            return raw
    return None


def field_name(line: bytes):
    i = line.find(b":")
    return None if i < 0 else line[:i]


def is_valid_name(name: bytes):
    return bool(name) and all(c in VALID_NAME_CHARS for c in name)


def analyse(raw: bytes, names):
    cut = raw.find(SEPARATOR)
    if cut < 0:
        header, body, header_end = raw, b"", len(raw)
    else:
        header, body, header_end = raw[:cut], raw[cut + 4:], cut
    body_offset = header_end + 4

    hlines = header.split(CRLF)
    blines = body.split(CRLF)

    logical, offsets, pos = [], [], 0
    for ln in hlines:
        if ln[:1] in (b" ", b"\t") and logical:
            logical[-1] += CRLF + ln
        else:
            logical.append(ln)
            offsets.append(pos)
        pos += len(ln) + 2

    malformed_idx = [i for i, hl in enumerate(logical)
                     if not is_valid_name(field_name(hl))]
    first_malformed = offsets[malformed_idx[0]] if malformed_idx else None

    def count_prefix(lines, prefix):
        return sum(1 for l in lines if l.startswith(prefix))

    received_body = (
        count_prefix(blines, b"Received:")
        + count_prefix(blines, b"Received :")
        + count_prefix(blines, "Receíved:".encode())
    )

    name_stats = {}
    for n in names:
        want = n.lower()
        in_header = sum(
            1 for hl in logical
            if (fn := field_name(hl)) is not None and fn.strip().lower() == want.encode()
        )
        in_body = sum(1 for l in blines if l.lower().startswith(want.encode()))
        name_stats[n] = (in_header, in_body)

    return {
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes": len(raw),
        "header_section_bytes": len(header),
        "header_end_offset": header_end,
        "body_offset": body_offset,
        "first_malformed_offset": first_malformed,
        "logical_headers": len(logical),
        "received_exact": count_prefix(hlines, b"Received:"),
        "received_ci": sum(
            1 for hl in logical
            if (fn := field_name(hl)) is not None and fn.strip().lower() == b"received"
        ),
        "received_space": count_prefix(hlines, b"Received :"),
        "received_utf8": count_prefix(hlines, "Receíved:".encode()),
        "received_in_body": received_body,
        "malformed_in_header": len(malformed_idx),
        "largest_header_bytes": max((len(h) for h in logical), default=0),
        "names": name_stats,
    }


def fmt(metrics):
    keys = ("raw_sha256", "raw_bytes", "header_section_bytes", "header_end_offset",
            "body_offset", "first_malformed_offset", "logical_headers",
            "received_exact", "received_ci", "received_space", "received_utf8",
            "received_in_body", "malformed_in_header", "largest_header_bytes")
    out = [f"{k.upper()}: {'' if metrics[k] is None else metrics[k]}" for k in keys]
    for n, (h, b) in metrics["names"].items():
        out.append(f"NAME {n}: header={h} body={b}")
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case-id", default=None)
    p.add_argument("--file", default=None, help="analyse a local .eml file instead of Mailpit")
    p.add_argument("--timeout", type=float, default=12)
    p.add_argument("--name", action="append", default=None, dest="names",
                   help="field name to count (repeatable)")
    p.add_argument("--save", default=None, help="directory to write raw/sha256/parsed.json")
    a = p.parse_args()

    if a.file:
        with open(a.file, "rb") as f:
            raw = f.read()
        case = a.case_id or "FILE"
    else:
        if not a.case_id:
            p.error("--case-id or --file is required")
        case = a.case_id
        deadline = time.time() + a.timeout
        raw = None
        while time.time() < deadline and raw is None:
            raw = find_raw_by_case(case)
            if raw is None:
                time.sleep(0.4)
        if raw is None:
            print("FOUND: no")
            sys.exit(1)
        print("FOUND: yes")

    metrics = analyse(raw, a.names or [])
    if a.save:
        import os
        os.makedirs(a.save, exist_ok=True)
        base = os.path.join(a.save, f"{case}.raw")
        with open(base + ".eml", "wb") as f:
            f.write(raw)
        with open(base + ".sha256", "w") as f:
            f.write(metrics["raw_sha256"] + "\n")
        with open(os.path.join(a.save, f"{case}.parsed.json"), "w") as f:
            json.dump(metrics, f, indent=2)
    print(fmt(metrics))


if __name__ == "__main__":
    main()
