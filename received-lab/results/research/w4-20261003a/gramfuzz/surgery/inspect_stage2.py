import json
import subprocess
from pathlib import Path

stage = Path("/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz")
rows = json.loads((stage / "stage2.json").read_text(encoding="utf-8"))


def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return p.stdout + p.stderr


print("=== exim/osmtpd delivery fate for attribution-bad cases ===")
for case in ("gf-received-guided.tab-colon-0012", "gf-obs-received-guided.tab-colon-0002",
             "gf-sender-guided.tab-colon-0007", "gf-arc-ams-guided.tab-colon-0007"):
    out = sh(["docker", "logs", "exim", "--since", "90m"])
    hits = [ln for ln in out.splitlines() if case in ln]
    print("EXIM", case, len(hits), "log lines; tail:", hits[-2:] if hits else None)
    out = sh(["docker", "logs", "opensmtpd", "--since", "90m"])
    hits = [ln for ln in out.splitlines() if case in ln]
    print("OSMTPD", case, len(hits), "log lines; tail:", hits[-2:] if hits else None)

print()
print("=== postfix delivery fate for one not-found obs-from case ===")
out = sh(["docker", "logs", "msl-auth-postfix", "--since", "90m"])
for case in ("gf-obs-from-fresh-0002", "gf-obs-from-guided.dup-line-0005"):
    hits = [ln for ln in out.splitlines() if case in ln]
    print(case, len(hits), "lines:")
    for ln in hits[-3:]:
        print("   ", ln[:220])

print()
print("=== raw JSON of one delivered IMAP row (search keys?) ===")
for r in rows:
    im = r.get("imap") or {}
    if im.get("uid"):
        print(r["case"])
        print(json.dumps(im, ensure_ascii=False)[:600])
        break

print()
print("=== search probe manual test ===")
import base64
import sys
sys.path.insert(0, "/mnt/e/Gramfuzz")
import gramfuzz.funnel as gf
queries = [["gf-from-guided.tab-colon-0001|hdr",
            base64.b64encode(b"~$!.%^.+}~@[]").decode()]]
code, out, err = gf.diffrun.sh(
    ["docker", "exec", "-i", "msl-client", "python3", "-", json.dumps(queries)],
    timeout=120, stdin=gf._IMAP_PROBE_SEARCH.encode())
print("code", code, "out", out[:400], "err", err[:200])
