#!/usr/bin/env python3
"""KB3-reverse: TWO From headers, first=mallory second=alice.
Signer (dkimpy) hashes the FIRST instance => signature covers mallory.
Verifiers that select FIRST instance will PASS a message whose visible
(first) From is mallory; verifiers that select LAST will compute bh over
alice and FAIL. Usage: mk_kb3rev.py OUT"""
import sys

out = sys.argv[1]
hdrs = [f"X-Case-ID: KB3-rev",
        "From: Mallory <mallory@evil.example>",
        "To: Bob <bob@receiver.lab.test>",
        "Subject: KB3-reverse first=mallory",
        f"Message-ID: <kb3rev@sender.lab.test>",
        "From: Alice <alice@sender.lab.test>",
        f"Message-ID: <kb3rev2@sender.lab.test>",
        "", "KB3 reverse body."]
data = ("\r\n".join(hdrs) + "\r\n").encode()
open(out, "wb").write(data)
print(out, len(data), "bytes (first From=mallory, second From=alice)")
