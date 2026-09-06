#!/usr/bin/env python3
"""J3: remove the first header line (the anomaly) from the stored message,
restoring the header block. usage: j3_repair.py STORED_FILE OUT_FILE"""
import sys

raw = open(sys.argv[1], "rb").read()
i = raw.find(b"\r\n")
repaired = raw[i + 2:]
open(sys.argv[2], "wb").write(repaired)
print("repaired: removed first line ->", len(repaired), "bytes")
