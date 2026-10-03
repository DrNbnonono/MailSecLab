"""Route C: how verifiers build the _domainkey query name from odd d=/s=.

Each case keeps a mathematically valid b= for the published lab key. The
public key is published for lab.test, evil.test and the IDN domain, so any
qname a verifier constructs from these tags can resolve. Observables:
verifier status, the AR/OpenDKIM header.d after the chain, and the qname
each component actually asked the resolver (from the msl-dns log).
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
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "qname"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
EVIDENCE = "/evidence/w2-20261002a/qname"
H_NAMES = ["from", "to", "date", "subject", "message-id"]


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def sign_custom(raw: bytes, middle_tags: bytes) -> bytes:
    info = structure.require_modern(raw)
    body = reference.canonical_body(raw[info["boundary"] + 4:], "relaxed")
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; " + middle_tags + b";\r\n h=" + ":".join(H_NAMES).encode() + b";\r\n bh=" + bh + b"; b=\r\n"
    hashed, _ = reference.hashing_input(raw, signature, H_NAMES, "relaxed")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b"\r\n"
    return signature + raw


CASES = [
    {"name": "c1-upper-ds", "middle": b"d=LAB.TEST;\r\n s=CAL"},
    {"name": "c2-trailing-dot-d", "middle": b"d=lab.test.;\r\n s=cal"},
    {"name": "c3-fws-in-d", "middle": b"d=lab\r\n\t.test;\r\n s=cal"},
    {"name": "c4-duplicate-d", "middle": b"d=lab.test;\r\n d=evil.test;\r\n s=cal"},
]


def build(case_id: str) -> bytes:
    headers = [
        b"From: Author <author@lab.test>",
        b"To: bob@lab.test",
        b"Date: Fri, 2 Oct 2026 14:25:00 +0000",
        b"Subject: qname construction probe",
        f"Message-ID: <{case_id}@lab.test>".encode(),
        f"X-Case-ID: {case_id}".encode(),
    ]
    return b"\r\n".join(headers) + b"\r\n\r\nControlled research body.\r\nCase: " + case_id.encode() + b"\r\n"


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
    blob = msg[0][1] if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/qname/{case}.stored.eml", "wb").write(raw)
    ar = [l.decode("utf-8", "replace") for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "bytes": len(raw), "ar": ar}
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
        case_id = "qnp-" + name
        raw = build(case_id)
        signed = sign_custom(raw, case["middle"])
        (STAGE / f"{name}.eml").write_bytes(signed)
        t_verify = time.strftime("%H:%M:%S")
        verdicts = verify_file(f"{EVIDENCE}/{name}.eml")
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
            sent = {"accepted": False, "raw": (out or err)[-300:]}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        row = {
            "case": name,
            "middle_tags": case["middle"].decode("latin1"),
            "t_verify": t_verify,
            "t_send": t_send,
            "verifiers": {k: v.get("status") for k, v in verdicts.items()},
            "smtp_reply": sent.get("reply"),
            "ar": stored.get("ar", []),
            "sha256": sha256_bytes(signed),
        }
        write_json(STAGE / f"{name}.json", {"row": row, "verifiers": verdicts})
        rows.append(row)
        print(json.dumps({"case": name, "verifiers": row["verifiers"], "reply": (sent.get("reply") or "")[:50], "ar": [a[:90] for a in row["ar"]]}), flush=True)
        time.sleep(4)
    write_json(STAGE / "cases.json", {"rows": rows})


if __name__ == "__main__":
    main()
