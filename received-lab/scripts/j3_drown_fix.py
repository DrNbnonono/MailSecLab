#!/usr/bin/env python3
"""J3 final: remove ONLY the Receíved anomaly line, keep everything else.
usage: j3_drown_fix.py STORED_FILE OUT_FILE"""
import sys
raw = open(sys.argv[1], "rb").read()
lines = raw.replace(b"\r\n", b"\n").split(b"\n")
kept = [l for l in lines if not l.startswith(b"Rece\xc3\xadved:")]
open(sys.argv[2], "wb").write(b"\n".join(kept))
print(f"removed {len(lines)-len(kept)} anomaly line(s); kept {len(kept)} lines")
