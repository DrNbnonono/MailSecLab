#!/usr/bin/env python3
"""Build the Phase 3A byte-fixed corpus (V001..V012).

Deterministic: fixed base date, CRLF endings, X-Case-ID as the very first
header. Writes VXXX.eml files plus manifest.json (description, byte count and
sha256 per case). Run inside the client container with --out /results/...
or on the host; the bytes only depend on the case ids, never on clock time.
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta

BASE = datetime(2026, 8, 31, 12, 0, 0)  # fixed -> deterministic bytes


def ts(i):
    return (BASE - timedelta(seconds=i + 1)).strftime("%a, %d %b %Y %H:%M:%S +0800")


def msg(case, injected):
    lines = [f"X-Case-ID: {case}"] + injected + [
        "From: Alice <alice@sender.lab.test>",
        "To: Bob <bob@receiver.lab.test>",
        f"Subject: [{case}] received-experiment",
        f"Message-ID: <{case}@sender.lab.test>",
        "",
        "Phase 3A corpus body.",
    ]
    return ("\r\n".join(lines) + "\r\n").encode()


def received_line(case, i, name="Received"):
    return (f"{name}: from fake{i:03d}.lab.test by fake{(i + 1) % 1000:03d}.lab.test "
            f"with ESMTP id {case}-{i:03d}; {ts(i)}")


def folded(case, i, kb):
    target = kb * 1024
    head = (f"Received: from fold{i:03d}.lab.test "
            f"by fold{(i + 1):03d}.lab.test with ESMTP id {case}-FOLD{i:03d};")
    first = f"{head}\r\n {ts(i)}"
    cont = " (" + "A" * 894 + ")"
    parts, size = [first], len(first) + 2
    while size < target:
        parts.append(cont)
        size += len(cont) + 2
    parts.append(f" {ts(i + 1)}")
    return "\r\n".join(parts)


def build_cases():
    c = {}
    c["V001"] = ("normal message", msg("V001", []))
    c["V002"] = ("Received x46 (deliver boundary)", msg("V002", [received_line("V002", i) for i in range(46)]))
    c["V003"] = ("Received x47 (P3 reject boundary)", msg("V003", [received_line("V003", i) for i in range(47)]))
    c["V004"] = ("rEcEiVeD x46 (case-insensitive counting)", msg("V004", [received_line("V004", i, "rEcEiVeD") for i in range(46)]))
    c["V005"] = ("'Received :' (space before colon) x5", msg("V005", [f"Received : from fake{i:03d}.lab.test by fake{i + 1:03d}.lab.test; {ts(i)}" for i in range(5)]))
    c["V006"] = ("'Received<TAB>:' x5", msg("V006", [f"Received\t: from fake{i:03d}.lab.test by fake{i + 1:03d}.lab.test; {ts(i)}" for i in range(5)]))
    c["V007"] = ("Receíved: x1 (non-US-ASCII field-name)", msg("V007", [f"Receíved: from fake000.lab.test by fake001.lab.test; {ts(0)}"]))
    c["V008"] = ("Receíved: x50 (non-US-ASCII field-name)", msg("V008", [f"Receíved: from fake{i:03d}.lab.test by fake{i + 1:03d}.lab.test; {ts(i)}" for i in range(50)]))
    c["V009"] = ("BROKEN_HEADER line without colon", msg("V009", ["BROKEN_HEADER this line has no colon"]))
    c["V010"] = ("Subject x50 (max-1 field duplicated)", msg("V010", [f"Subject: dup {i:02d} [{ts(i)}]" for i in range(50)]))
    c["V011"] = ("folded Received ~90KB x1", msg("V011", [folded("V011", 0, 90)]))
    c["V012"] = ("folded Received ~150KB x1 (> header_size_limit)", msg("V012", [folded("V012", 0, 150)]))
    return c


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "results", "phase3", "corpus"))
    a = p.parse_args()
    os.makedirs(a.out, exist_ok=True)

    manifest = {}
    for case, (desc, raw) in build_cases().items():
        path = os.path.join(a.out, f"{case}.eml")
        with open(path, "wb") as f:
            f.write(raw)
        manifest[case] = {
            "description": desc,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    with open(os.path.join(a.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    for case, info in manifest.items():
        print(f"{case}  {info['bytes']:>7}B  {info['sha256'][:12]}…  {info['description']}")


if __name__ == "__main__":
    main()
