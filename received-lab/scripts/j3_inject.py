#!/usr/bin/env python3
"""J3: prepend the Receíved anomaly header (unsigned) in front of the signed
message. Signature covers only h= headers, so prepending an unsigned header
does not break it. usage: j3_inject.py SIGNED_FILE OUT_FILE"""
import sys

sig = open(sys.argv[1], "rb").read()
anomaly = ("Receíved: from spoofer.lab.test by spoofer.lab.test; "
           "Tue, 1 Jan 2030 00:00:00 +0000\r\n").encode("utf-8")
open(sys.argv[2], "wb").write(anomaly + sig)
print("injected", len(anomaly), "bytes anomaly before signed header block")
