#!/usr/bin/env python3
"""J-series DKIM sign. usage: dkim_sign.py IN OUT SELECTOR DOMAIN len(true|false) [hlist]"""
import sys
import dkim

inp, outp, selector, domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
uselen = sys.argv[5] == "true"
hlist = (sys.argv[6] if len(sys.argv) > 6 else "from,to,subject,message-id").split(",")
msg = open(inp, "rb").read()
key = open("/results/j-series/dkim.key", "rb").read()
d = dkim.DKIM(msg)
sig = d.sign(selector.encode(), domain.encode(), key,
             include_headers=[h.strip().encode() for h in hlist],
             length=uselen, canonicalize=(b"relaxed", b"relaxed"))
open(outp, "wb").write(sig + msg)
print(f"signed {len(sig)+len(msg)} bytes l={uselen} h={hlist}")
