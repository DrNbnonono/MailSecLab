"""stage-2 wiring precheck: KB2 anchor, one relay case, one IMAP case."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/Gramfuzz")
import gramfuzz.funnel as gf

run_id = "w4-20261003a"
stage = gf.RUN_ROOT / run_id / "gramfuzz"

# 1) KB2-style anchor precheck (scratch id; the real run uses gf-sign-anchor-kb2)
anchor = gf._sign_one(run_id, stage, "gf-sign-precheck-kb2", gf.KB2_INJECT)
print("ANCHOR file:", json.dumps(anchor["file"]), flush=True)
print("ANCHOR postfix:",
      json.dumps({k: (anchor.get("postfix") or {}).get(k)
                  for k in ("smtp_code", "captured")}), flush=True)
print("ANCHOR postfix verdicts:",
      json.dumps((anchor.get("postfix") or {}).get("verdicts")), flush=True)
print("KB2 MATCH:", anchor["file"] == gf.KB2_EXPECT, flush=True)

# 2) relay arm on one survivor x 3 targets
index = {i["case"]: i for i in json.loads(
    (stage / "corpus-index.json").read_text(encoding="utf-8"))}
survivors = json.loads((stage / "survivors.json").read_text(encoding="utf-8"))
problems = []
case = survivors[0]
raw = (stage / "corpus" / ("%s.eml" % case)).read_bytes()
gen = bytes.fromhex(index[case]["gen_bytes"])
targets, _ = gf.diffrun.load_config()
for target, (server, port) in targets.items():
    row = gf._relay_one(run_id, stage, case, target, server, port, raw, gen, problems)
    print("RELAY", case, target,
          json.dumps({k: row.get(k) for k in ("smtp_code", "captured",
                                              "gen_preserved", "attribution",
                                              "error")}), flush=True)
    time.sleep(0.8)

# 3) IMAP arm on one from-family survivor
from_family = [c for c in survivors if index[c]["entry"] in gf.IMAP_ENTRIES]
icase = from_family[0]
irows = gf._imap_arm(run_id, stage, [icase], index, problems)
print("IMAP", icase, json.dumps(irows.get(icase), ensure_ascii=False), flush=True)
print("problems:", json.dumps(problems, ensure_ascii=False), flush=True)
