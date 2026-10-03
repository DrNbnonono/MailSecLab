import base64
import json
import subprocess
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")
import gramfuzz.funnel as gf

FETCH = r"""
import base64, imaplib, json, sys

def _flat(x, out=None):
    if out is None:
        out = []
    if isinstance(x, (tuple, list)):
        for i in x:
            _flat(i, out)
    elif isinstance(x, bytes):
        out.append(x)
    return out

m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, msg = m.uid("FETCH", "2817", "(ENVELOPE)")
print(json.dumps([base64.b64encode(p).decode("latin-1") for p in _flat(msg)]))
m.logout()
"""

proc = subprocess.run(["docker", "exec", "-i", "msl-client", "python3", "-"],
                      input=FETCH.encode(), capture_output=True, timeout=60)
parts = [base64.b64decode(p) for p in json.loads(proc.stdout.decode().strip())]
print("parts:", len(parts))
for p in parts:
    print("  ", repr(p)[:120])
toks = gf._imap_tokens(parts)
print("tokens:", len(toks))
for t in toks:
    print("  T:", repr(t)[:100])
nest = gf._nested(toks)
print("nested[0]:", repr(nest[0])[:80])
print("nested[1]:", repr(nest[1])[:200] if len(nest) > 1 else None)
print("find:", repr(gf._find_envelope(nest))[:200])
print("slot:", gf._envelope_from_slot(parts))
