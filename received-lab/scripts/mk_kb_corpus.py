#!/usr/bin/env python3
"""K1 corpus generator: KB1-KB5 boundary cases for DKIM verifier differential.
usage: mk_kb_corpus.py OUT
All messages are SIGNED-READY bases; signing happens in the driver (dkimpy).
Self-check per G-series lesson: header line count, no double CRLF in header
section, no leading blank line, exactly one header/body separator.
"""
import os, sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)

def hdr_id(case):
    return ["From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
            f"Subject: K1 {case}", f"Message-ID: <{case.lower()}@sender.lab.test>"]

def write(case, hdrs, body="K body."):
    data = ("\r\n".join(hdrs + ["", body]) + "\r\n").encode()
    p = os.path.join(OUT, case + ".eml")
    open(p, "wb").write(data)
    # --- self-check (G-series lesson) ---
    i = data.find(b"\r\n\r\n")
    assert i > 0, f"{case}: no header/body separator"
    hdr = data[:i]
    lines = hdr.split(b"\r\n")
    assert all(l for l in lines), f"{case}: empty header line inside header block"
    assert data[i+4:i+5] not in (b"\n", b"\r"), f"{case}: stray newline after separator"
    assert b"\r\n\r\n" not in hdr, f"{case}: DOUBLE CRLF inside header section"
    print(f"{p} {len(data)}B hdr_lines={len(lines)} selfcheck=OK")

# KB1: clean reference
write("KB1-clean", [f"X-Case-ID: KB1-clean"] + hdr_id("KB1-clean"))

# KB2: clean message that will get an anomaly header injected AFTER signing
#      (driver prepends "Receíved..." line post-signing, like J3)
write("KB2-base", [f"X-Case-ID: KB2-anomaly"] + hdr_id("KB2-anomaly"))

# KB3: duplicate From and Subject (RFC 5322 max-1 violated); multiple valid
#      signature instances let verifiers pick different From instances
write("KB3-dupfrom", [f"X-Case-ID: KB3-dupfrom"] + hdr_id("KB3-dupfrom")[:1] + [
    "From: Mallory <mallory@evil.example>",
    "To: Bob <bob@receiver.lab.test>",
    "Subject: K1 KB3-dupfrom SECOND INSTANCE",
    f"Message-ID: <kb3b@sender.lab.test>"])

# KB4: second header block appended after the body (loose parsers may accept)
c4 = "KB4-secondblock"
data = (f"X-Case-ID: {c4}\r\n" + "\r\n".join(hdr_id(c4)) + "\r\n\r\n"
        "first body line.\r\n"
        "Bcc: hidden@evil.example\r\n"
        "From: Mallory <mallory@evil.example>\r\n"
        "Subject: INJECTED SECOND HEADER BLOCK\r\n"
        "\r\n"
        "second block body.\r\n").encode()
p = os.path.join(OUT, c4 + ".eml")
open(p, "wb").write(data)
print(f"{p} {len(data)}B (two header blocks by design; selfcheck skipped)")

# KB5: signed with l= AND body contains header-shaped lines (parse arbitrage:
# Go/Node-style parsers that treat them as headers vs DKIM body hash)
c5 = "KB5-lplusheaders"
data = (f"X-Case-ID: {c5}\r\n" + "\r\n".join(hdr_id(c5)) + "\r\n\r\n"
        "signed body per l=.\r\n"
        "From: Mallory <mallory@evil.example>\r\n"
        "Subject: FORGED HEADER-LOOKING LINES IN BODY\r\n"
        "Received: from evil.example by evil.example; Tue, 1 Jan 2030 00:00:00 +0000\r\n"
        "\r\n"
        "trailing body.\r\n").encode()
p = os.path.join(OUT, c5 + ".eml")
open(p, "wb").write(data)
print(f"{p} {len(data)}B (header-shaped body lines by design)")
