#!/usr/bin/env python3
"""J3 message builder. usage: mk_j3_msg.py OUT [mode]
mode=clean (default): no anomaly line  -> used as DKIM signing base
mode=anomaly:         V007-class Receíved terminator included"""
import sys

out, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "clean")
anomaly = ("Receíved: from spoofer.lab.test by spoofer.lab.test; "
           "Tue, 1 Jan 2030 00:00:00 +0000\r\n")
hdrs = [f"X-Case-ID: J3-relay"]
if mode == "anomaly":
    hdrs.append(anomaly.rstrip("\r\n"))
hdrs += ["From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
         "Subject: J3 boundary differential", "Message-ID: <j3@sender.lab.test>",
         "", "J3 body."]
data = ("\r\n".join(hdrs) + "\r\n").encode()
open(out, "wb").write(data)
print(out, len(data), "bytes mode=" + mode)
