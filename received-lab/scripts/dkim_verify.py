#!/usr/bin/env python3
"""J-series DKIM verify WITHOUT DNS: dnsfunc override returns the local
public key record. usage: dkim_verify.py MSG_FILE"""
import sys
import dkim

msg = open(sys.argv[1], "rb").read()
record = b"v=DKIM1; k=rsa; p=" + open("/results/j-series/dkim.pub.txt", "rb").read().strip()

def dnsfunc(name, timeout=5):
    print(f"[dns] lookup {name.decode()} -> override record", file=sys.stderr)
    return record

d = dkim.DKIM(msg)
try:
    ok = d.verify(dnsfunc=dnsfunc)
    print("VERIFY:", "pass" if ok else "FAIL")
except Exception as e:
    print("VERIFY: ERROR", repr(e)[:140])
