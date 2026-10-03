"""Route A follow-up: enforcement flip under RejectFailures=true.

Pair test: the same spoofed victim identity, once as A-label (policy found)
and once as raw UTF-8 U-label (policy lookup misses). Controls: a correctly
signed A-label message, and a foreign-signed U-label spoof. OpenDMARC config
is edited in place, the container restarted, and reverted afterwards.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "eai-enforce"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
EVIDENCE = "/evidence/w2-20261002a/eai-enforce"
VICTIM_ALABEL = "xn--mnchen-3ya.lab.test"
VICTIM_ULABEL = "münchen.lab.test"


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def wait_milter(port: int = 8893, seconds: float = 60.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        code, out, _ = sh([
            "docker", "exec", "msl-client", "python3", "-c",
            f"import socket; s=socket.create_connection(('msl-opendmarc',{port}),timeout=2); s.close()",
        ], timeout=15)
        if code == 0:
            return True
        time.sleep(1.5)
    return False


def build(case_id: str, from_line: str, sign: bool) -> bytes:
    headers = [
        from_line.encode("utf-8"),
        b"To: recipient@receiver.test",
        b"Date: Fri, 2 Oct 2026 13:00:00 +0000",
        b"Subject: eai enforcement probe",
        f"Message-ID: <{case_id}@lab.test>".encode(),
        f"X-Case-ID: {case_id}".encode(),
    ]
    raw = b"\r\n".join(headers) + b"\r\n\r\nControlled research body.\r\nCase: " + case_id.encode() + b"\r\n"
    if not sign:
        return raw
    signed, _ = reference.sign(raw, KEY, ["from", "to", "date", "subject", "message-id"],
                               mode="relaxed", domain="lab.test", selector="cal")
    return signed


CASES = [
    {"name": "x1-alabel-spoof", "from": f"From: Spoofed <author@{VICTIM_ALABEL}>", "sign": False},
    {"name": "x2-ulabel-spoof", "from": f"From: Spoofed <author@{VICTIM_ULABEL}>", "sign": False},
    {"name": "x3-ulabel-spoof-signed-foreign", "from": f"From: Spoofed <author@{VICTIM_ULABEL}>", "sign": True},
    {"name": "x4-alabel-legit-signed", "from": f"From: Author <author@{VICTIM_ALABEL}>", "sign": "victim"},
]

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
    if case.encode() not in blob and case.encode() not in (msg[0][1] if msg and msg[0] else b""):
        continue
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/eai-enforce/{case}.stored.eml", "wb").write(raw)
    ar = [l.decode("utf-8", "replace") for l in raw.split(b"\r\n") if l.lower().startswith(b"authentication-results")]
    out = {"found": True, "uid": item.decode(), "bytes": len(raw), "ar": ar}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 8, delay: float = 3.0):
    for _ in range(tries):
        code, out, err = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                            timeout=60, stdin=FETCH_SCRIPT.encode())[:1] + (None,) * 0 or (None, None, None)
        break
    return {}


def fetch_loop(case_id: str, tries: int = 8, delay: float = 3.0) -> dict:
    last = {"found": False}
    for _ in range(tries):
        proc = subprocess.run(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                              input=FETCH_SCRIPT.encode(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60, check=False)
        try:
            last = json.loads(proc.stdout.decode())
        except json.JSONDecodeError:
            last = {"found": False, "raw": proc.stdout.decode()[-200:] + proc.stderr.decode()[-200:]}
        if last.get("found"):
            return last
        time.sleep(delay)
    return last


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    code, out, err = sh(["docker", "exec", "msl-opendmarc", "grep", "RejectFailures", "/etc/opendmarc.conf"])
    before = out.strip()
    sh(["docker", "exec", "msl-opendmarc", "sed", "-i", "s/^RejectFailures false/RejectFailures true/", "/etc/opendmarc.conf"])
    sh(["docker", "restart", "msl-opendmarc"])
    if not wait_milter():
        raise SystemExit("opendmarc milter did not come back")
    code, out, _ = sh(["docker", "exec", "msl-opendmarc", "grep", "RejectFailures", "/etc/opendmarc.conf"])
    flipped = out.strip()
    print("RejectFailures:", before, "->", flipped, flush=True)
    try:
        for case in CASES:
            name = case["name"]
            case_id = "eaienf-" + name
            sign = case["sign"]
            if sign == "victim":
                raw = build(case_id, case["from"], sign=False)
                signed, _ = reference.sign(raw, KEY, ["from", "to", "date", "subject", "message-id"],
                                           mode="relaxed", domain=VICTIM_ALABEL, selector="cal")
            else:
                signed = build(case_id, case["from"], sign=bool(sign))
            (STAGE / f"{name}.eml").write_bytes(signed)
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
            stored = fetch_loop(case_id) if sent.get("accepted") else {"found": False}
            row = {
                "case": name,
                "from": case["from"],
                "signed": str(sign),
                "sha256": sha256_bytes(signed),
                "smtp_reply": sent.get("reply"),
                "accepted": sent.get("accepted"),
                "delivered": stored.get("found"),
                "ar": stored.get("ar", []),
            }
            write_json(STAGE / f"{name}.json", {"row": row, "smtp": sent, "stored": stored})
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
            time.sleep(3)
    finally:
        sh(["docker", "exec", "msl-opendmarc", "sed", "-i", "s/^RejectFailures true/RejectFailures false/", "/etc/opendmarc.conf"])
        sh(["docker", "restart", "msl-opendmarc"])
        wait_milter()
    write_json(STAGE / "cases.json", {"before": before, "flipped": flipped, "rows": rows})


if __name__ == "__main__":
    main()
