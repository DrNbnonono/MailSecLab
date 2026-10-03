"""User-directed: Received/IMF differential fuzzing across three MTAs.

Same malformed Received inputs to Postfix (direct), Exim, OpenSMTPD; compare
preserve / normalize / reject / truncate / Received-append behaviours.
Delivery path: relay -> msl-auth-postfix -> Dovecot; the direct column
isolates auth-postfix's own transform, so relay-vs-direct differences
attribute to the relay MTA.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "recfuzz"
EVIDENCE = "/evidence/w2-20261002a/recfuzz"

PATHS = {"direct": ("msl-auth-postfix", 25), "exim": ("10.88.0.4", 25), "osmtpd": ("opensmtpd", 25)}

GOOD = "Received: from relay.lab.test (relay.lab.test [203.0.113.99]) by mx.bank.test with ESMTP id ABC123; Sat, 03 Oct 2026 20:00:00 +0000"

CASES = {
    "r01-good": GOOD,
    "r02-obs-colon": "Received : from a.lab.test (a.lab.test [203.0.113.1]) by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r03-case": "rEcEiVeD: from a.lab.test (a.lab.test [203.0.113.1]) by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r04-nocolon": "Received from a.lab.test by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r05-empty": "Received:",
    "r06-8bit-value": "Received: from m\u00fcnchen.lab.test (m\u00fcnchen.lab.test [203.0.113.2]) by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r07-8bit-name": "Rece\u00edved: from a.lab.test by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r08-no-semi": "Received: from a.lab.test (a.lab.test [203.0.113.1]) by b.lab.test with ESMTP id X",
    "r09-double-semi": "Received: from a.lab.test by b.lab.test;; Sat, 03 Oct 2026 20:00:00 +0000",
    "r10-comment-nest": "Received: from a.lab.test ((comment) [203.0.113.1] (x)) by b.lab.test; Sat, 03 Oct 2026 20:00:00 +0000",
    "r11-fold-long": "Received: from a.lab.test by b.lab.test\r\n " + "x" * 120 + "\r\n " + "y" * 120 + "; Sat, 03 Oct 2026 20:00:00 +0000",
    "r12-many": "\r\n".join(["Received: from h%d.lab.test by h%d.lab.test; Sat, 03 Oct 2026 19:%02d:00 +0000" % (i, i + 1, i) for i in range(10)]),
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
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1] if msg and msg[0] else b""
    if case.encode() not in raw:
        continue
    open(f"/evidence/w2-20261002a/recfuzz/{case}.stored.eml", "wb").write(raw)
    out = {"found": True, "uid": item.decode(), "bytes": len(raw)}
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


def rec_facts(orig: bytes, stored: bytes) -> dict:
    zone = stored[:stored.find(b"\r\n\r\n")]
    body = stored[stored.find(b"\r\n\r\n") + 4:]
    received_lines = [l for l in zone.split(b"\r\n") if l.lower().startswith((b"received", b"received :"))]
    appended = sum(1 for l in received_lines if b"mailseclab-research-net" in l or b"by exim" in l or b"by opensmtpd" in l or b"by auth-postfix" in l)
    return {
        "received_count_zone": len(received_lines),
        "obs_colon_survives": b"Received :" in stored,
        "case_variant_survives": b"rEcEiVeD" in stored,
        "nocolon_in_zone": any(l.startswith(b"Received from") for l in zone.split(b"\r\n")),
        "nocolon_in_body": b"Received from" in body[:300],
        "bit8_value_survives": b"m\xc3\xbcnchen" in stored,
        "bit8_name_sank": b"Rece\xc3\xadved" in body[:300],
        "bit8_name_in_zone": b"Rece\xc3\xadved" in zone,
        "mailbox_line": b"X-Mailbox-Line" in stored,
        "relay_received": appended,
    }


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, rec in CASES.items():
        for path, (server, port) in PATHS.items():
            case_id = f"rf-{name}-{path}"
            raw = (rec.encode("utf-8") + b"\r\n"
                   + b"From: Bank Security <security@bank.test>\r\n"
                   + b"To: bob@lab.test\r\n"
                   b"Date: Sat, 3 Oct 2026 23:00:00 +0000\r\n"
                   + ("Subject: recfuzz %s\r\n" % name).encode()
                   + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
                   + ("X-Case-ID: %s\r\n" % case_id).encode()
                   + b"\r\nPlease confirm the payment.\r\n")
            (STAGE / f"{name}-{path}.eml").write_bytes(raw)
            code, out, err = sh([
                "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
                "--server", server, "--port", str(port),
                "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
                "--input", f"{EVIDENCE}/{name}-{path}.eml",
                "--transcript", f"{EVIDENCE}/{name}-{path}.smtp.txt",
            ], timeout=90)
            try:
                sent = json.loads(out)
            except json.JSONDecodeError:
                sent = {"accepted": False}
            stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
            spath = STAGE / f"{name}-{path}.stored.eml"
            facts = {}
            if spath.exists():
                facts = rec_facts(raw, spath.read_bytes())
            row = {"case": name, "path": path, "smtp_code": (sent.get("reply") or "")[:3],
                   "smtp": (sent.get("reply") or "")[:40], "delivered": stored.get("found"),
                   "facts": facts, "sha256": sha256_bytes(raw)}
            rows.append(row)
            f = row["facts"]
            print(json.dumps({"c": name, "p": path, "code": row["smtp_code"], "dlv": row["delivered"],
                              "rec": f.get("received_count_zone"), "obs": f.get("obs_colon_survives"),
                              "case": f.get("case_variant_survives"), "app": f.get("relay_received"),
                              "ml": f.get("mailbox_line")}, ensure_ascii=False), flush=True)
            time.sleep(0.8)
    (STAGE / "matrix.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
