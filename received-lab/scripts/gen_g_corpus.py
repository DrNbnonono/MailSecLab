#!/usr/bin/env python3
"""G-series corpus generator.
usage: gen_g_corpus.py OUT CASE N_HEADERS KB_EACH ORDER
  ORDER: from-last (From/To/Subject AFTER the giant block, F1 style)
         from-first (identity headers BEFORE the giant block)
"""
import os, sys

def folded(i, kb):
    target = kb * 1024
    first = f"X-Received: from g{i}.lab.test by g{i}.lab.test; Tue, 1 Jan 2030 00:00:00 +0000"
    cont = " (" + "A" * 894 + ")"
    parts, ln = [first], len(first)
    while ln < target:
        parts.append(cont); ln += len(cont) + 2
    return "".join(parts)

out, case, n, kb, order = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
ident = ["From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
         f"Subject: G {case}", "Message-ID: <g@sender.lab.test>"]
giants = [folded(i, kb) for i in range(n)]
if order == "from-first":
    hdrs = [f"X-Case-ID: {case}"] + ident + giants
else:
    hdrs = [f"X-Case-ID: {case}"] + giants + ident
hdrs += ["", "body."]
data = ((chr(13)+chr(10)).join(hdrs) + chr(13)+chr(10)).encode()
os.makedirs(out, exist_ok=True)
p = os.path.join(out, case + ".eml")
open(p, "wb").write(data)
print(f"{p} {len(data)} bytes order={order}")
