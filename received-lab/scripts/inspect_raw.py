#!/usr/bin/env python3
"""Locate a case message in Mailpit by X-Case-ID and analyse its raw structure.

Always reports: strict/whitespace/UTF-8 Received-line counts in header vs body,
plus optional --name counts (case-insensitive field names in the header section),
total logical headers, header section bytes and the largest logical header size.
"""
import argparse
import json
import sys
import time
import urllib.request

MP = "http://mailpit:8025"


def get_json(path):
    with urllib.request.urlopen(MP + path, timeout=8) as r:
        return json.loads(r.read().decode())


def get_raw(mid):
    with urllib.request.urlopen(MP + f"/api/v1/message/{mid}/raw", timeout=8) as r:
        return r.read().decode(errors="replace")


def find_by_case(case):
    for m in get_json("/api/v1/messages?limit=80").get("messages", []):
        raw = get_raw(m["ID"])
        if f"X-Case-ID: {case}" in raw.split("\r\n\r\n", 1)[0]:
            return m["ID"], raw
    return None, None


def analyse(raw, names):
    header_part, _, body_part = raw.partition("\r\n\r\n")
    lines = header_part.split("\r\n")

    logical = []
    for line in lines:
        if line[:1] in (" ", "\t") and logical:
            logical[-1] += "\r\n" + line
        else:
            logical.append(line)

    def name_of(header):
        return header.split(":", 1)[0]

    def count_in(section_lines, prefix):
        return sum(1 for l in section_lines if l.startswith(prefix))

    stats = {
        "RECEIVED_STRICT": (count_in(lines, "Received:"), count_in(body_part.split("\r\n"), "Received:")),
        "RECEIVED_SPACE": (count_in(lines, "Received :"), count_in(body_part.split("\r\n"), "Received :")),
        "RECEIVED_UTF8": (count_in(lines, "Receíved:"), count_in(body_part.split("\r\n"), "Receíved:")),
    }
    out = [f"FOUND: yes"]
    for k, (h, b) in stats.items():
        out.append(f"{k}: header={h} body={b}")
    for n in names:
        c = sum(1 for hl in logical if name_of(hl).strip().lower() == n.lower())
        out.append(f"NAME {n}: header={c}")
    out.append(f"TOTAL_LOGICAL_HEADERS: {len(logical)}")
    out.append(f"HEADER_SECTION_BYTES: {len(header_part)}")
    if logical:
        out.append(f"LARGEST_HEADER_BYTES: {max(len(hl) for hl in logical)}")
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case-id", required=True)
    p.add_argument("--timeout", type=float, default=12)
    p.add_argument("--name", action="append", default=None, dest="names",
                   help="field name to count in the header section (repeatable)")
    a = p.parse_args()

    deadline = time.time() + a.timeout
    mid = raw = None
    while time.time() < deadline and mid is None:
        mid, raw = find_by_case(a.case_id)
        if mid is None:
            time.sleep(0.4)

    if mid is None:
        print("FOUND: no")
        sys.exit(1)
    print(analyse(raw, a.names or []))


if __name__ == "__main__":
    main()
