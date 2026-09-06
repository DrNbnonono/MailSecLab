#!/usr/bin/env python3
"""J1 message: one 150KB folded X-Gen header (exceeds header_size_limit)
followed by normal identity headers. usage: mk_j1_msg.py OUT"""
import sys

first = "X-Gen: from big.lab.test by big.lab.test; Tue, 1 Jan 2030 00:00:00 +0000\r\n"
cont = " (" + "A" * 894 + ")\r\n"
parts, ln = [first], len(first)
while ln < 150 * 1024:
    parts.append(cont); ln += len(cont)
giant = "".join(parts).rstrip("\r\n")

hdrs = [f"X-Case-ID: J1-relay", giant,
        "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
        "Subject: J1 oversized header truncation", "Message-ID: <j1@sender.lab.test>",
        "", "J1 body ends here.\r\n"]
data = ("\r\n".join(hdrs) + "\r\n").encode()
open(sys.argv[1], "wb").write(data)
print(sys.argv[1], len(data), "bytes")
