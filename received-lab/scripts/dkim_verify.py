#!/usr/bin/env python3
"""K/J DKIM verify WITHOUT DNS: dnsfunc override with local public key record.
usage: dkim_verify.py MSG_FILE  (refuse-parse is reported, not fatal)"""
import sys
import dkim

msg = open(sys.argv[1], "rb").read()
record = b"v=DKIM1; k=rsa; p=" + open("/results/j-series/dkim.pub.txt", "rb").read().strip()

def dnsfunc(name, timeout=5):
    return record

try:
    d = dkim.DKIM(msg)
except Exception as e:
    print("VERIFY: REFUSE-PARSE", repr(e)[:100])
    sys.exit(0)
try:
    ok = d.verify(dnsfunc=dnsfunc)
    print("VERIFY:", "pass" if ok else "FAIL")
except Exception as e:
    print("VERIFY: ERROR", repr(e)[:120])
