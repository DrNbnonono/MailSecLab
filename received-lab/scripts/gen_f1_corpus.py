#!/usr/bin/env python3
"""F1 corpus: byte-channel messages (folded X-Received ~90KB each, hopcount-blind).
Writes .eml files to the given output dir. Run inside mail-client or on host."""
import os, sys

def folded(i):
    first = f"X-Received: from fake{i}.lab.test by fake{i}.lab.test; Tue, 1 Jan 2030 00:00:00 +0000"
    cont = " (" + "A" * 894 + ")"
    parts, ln = [first], len(first)
    while ln < 90000:
        parts.append(cont); ln += len(cont) + 2
    return "".join(parts)

def build(n, case):
    hdrs = [f"X-Case-ID: {case}"] + [folded(i) for i in range(n)] + [
        "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
        f"Subject: F1 byte channel {case}", "Message-ID: <f1@sender.lab.test>", "", "body."]
    return ((chr(13)+chr(10)).join(hdrs) + chr(13)+chr(10)).encode()

if __name__ == "__main__":
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    for n in (1, 5, 20, 50, 100):
        case = f"F1-XF{n:03d}"
        b = build(n, case)
        with open(os.path.join(outdir, f"{case}.eml"), "wb") as f:
            f.write(b)
        print(f"{case}.eml {len(b)} bytes")
