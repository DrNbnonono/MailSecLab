#!/usr/bin/env python3
"""Count Received-style lines in the header section of an .eml file."""
import json, re, sys

raw = open(sys.argv[1], "rb").read()
i = raw.find(b"\r\n\r\n")
hdr = raw[:i] if i >= 0 else raw
lines = hdr.split(b"\r\n")
def cnt(pat):
    return sum(1 for l in lines if re.match(pat, l, re.I))
res = {
    "header_lines": len(lines),
    "received_exact": cnt(rb"^Received:"),
    "received_wsp": cnt(rb"^Received[ \t]:"),
    "received_ci": cnt(rb"^received:"),
    "nonascii_received": sum(1 for l in lines if re.match(rb"^rece.[^\x00-\x7f]", l, re.I)),
    "xreceived": cnt(rb"^X-Received:"),
}
print(json.dumps(res))
