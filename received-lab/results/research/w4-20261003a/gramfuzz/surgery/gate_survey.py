import json
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from pathlib import Path
from research.lib.tracefacts import corpus_check

stage = Path("/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz")
survivors = json.loads((stage / "survivors.json").read_text())
index = {i["case"]: i for i in json.loads((stage / "corpus-index.json").read_text())}

block_relay = {}
block_sign = {}
for case in survivors:
    raw = (stage / "corpus" / ("%s.eml" % case)).read_bytes()
    problems = corpus_check(raw)
    if problems:
        block_relay[case] = problems
    gen = bytes.fromhex(index[case]["gen_bytes"])
    g = gen if gen.endswith(b"\r\n") else gen + b"\r\n"
    gproblems = corpus_check(g + b"From: Bank Security <security@lab.test>\r\nTo: bob@lab.test\r\n"
                             + b"Date: Sat, 3 Oct 2026 23:59:00 +0000\r\n"
                             + ("Subject: %s-sign\r\n" % case).encode()
                             + ("X-Case-ID: %s-sign\r\n" % case).encode()
                             + b"\r\nbody\r\n")
    if gproblems:
        block_sign[case] = gproblems

print("survivors:", len(survivors))
print("relay-arm blocked by corpus_check:", len(block_relay))
print("sign-arm blocked (gen over clean template):", len(block_sign))
from collections import Counter
c = Counter(p.split("(")[0].strip() for ps in block_relay.values() for p in ps)
print("relay block reasons:", dict(c))
c2 = Counter(p.split("(")[0].strip() for ps in block_sign.values() for p in ps)
print("sign block reasons:", dict(c2))
for k in list(block_relay)[:5]:
    print(" ex relay:", k, block_relay[k])
for k in list(block_sign)[:5]:
    print(" ex sign:", k, block_sign[k])
