import json
import subprocess
from pathlib import Path

stage = Path("/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz")


def sh(cmd, timeout=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


print("=== 1) not-found obs-from: postfix queue fate via transcript queue id ===")
for case in ("gf-obs-from-fresh-0002", "gf-obs-from-guided.dup-line-0005"):
    t = stage / "imap" / ("%s.smtp.txt" % case)
    if not t.exists():
        print(case, "no transcript")
        continue
    qid = ""
    for line in t.read_text().splitlines():
        if "queued as" in line:
            qid = line.split("queued as")[-1].strip()
    print(case, "queue:", qid)
    if qid:
        out = sh(["docker", "logs", "msl-auth-postfix", "--since", "3h"])
        for ln in out.splitlines():
            if qid in ln:
                print("   ", ln[:200])

print()
print("=== 2) attribution-bad: exim mainlog around the run + late mailpit arrivals ===")
out = sh(["docker", "exec", "exim", "sh", "-c",
          "grep -c 'capture@lab.test' /var/log/exim4/main 2>/dev/null; tail -30 /var/log/exim4/main 2>/dev/null | grep -E 'defer|fail|error' | tail -8"])
print("exim log capture count + recent deferrals:")
print(out[-1200:] if out.strip() else "(empty)")
out = sh(["docker", "exec", "opensmtpd", "sh", "-c",
          "tail -40 /var/log/maillog 2>/dev/null || true"])
print("osmtpd log tail:", out[-600:] if out.strip() else "(no maillog)")

print()
print("=== 3) mailpit: current copies of the 4 flagged cases (blank-subject scan) ===")
FETCH = r"""
import json, urllib.request
cases = ["gf-received-guided.tab-colon-0012", "gf-obs-received-guided.tab-colon-0002",
         "gf-sender-guided.tab-colon-0007", "gf-arc-ams-guided.tab-colon-0007"]
msgs = json.loads(urllib.request.urlopen(
    "http://msl-mailpit:8025/api/v1/messages?limit=100", timeout=10).read()).get("messages", [])
out = {}
for m in msgs:
    raw = urllib.request.urlopen(
        "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=10).read()
    for c in cases:
        if c.encode() in raw:
            relay = ("exim" if b"from exim.lab.test" in raw else
                     "osmtpd" if b"from opensmtpd.lab.test" in raw else
                     "postfix" if b"from auth-postfix" in raw else "none")
            out.setdefault(c, []).append({"created": m.get("Created"), "relay": relay,
                                          "subj": (m.get("Subject") or "")[:30], "len": len(raw)})
print(json.dumps(out))
"""
p = subprocess.run(["docker", "exec", "-i", "msl-client", "python3", "-"],
                   input=FETCH, capture_output=True, text=True, timeout=120)
print(p.stdout or p.stderr[-500:])
