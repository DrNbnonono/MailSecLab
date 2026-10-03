"""Reply-target binding probe: dual Reply-To instances, clean attacker From.

ENVELOPE returns all instances (proved in hdrfuzz3 aggregation). Which one
does each webmail's Reply action bind to? w1 tested single-Reply-To only.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "replyto"
EVIDENCE = "/evidence/w2-20261002a/replyto"

VICTIM = "xn--mnchen-3ya.lab.test"
DUAL = {
    "rt1-evil-first": f"Reply-To: Reply <reply@evil.test>\r\nReply-To: Bank <security@{VICTIM}>",
    "rt2-victim-first": f"Reply-To: Bank <security@{VICTIM}>\r\nReply-To: Reply <reply@evil.test>",
}


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    for name, dual in DUAL.items():
        case_id = "rtb-" + name
        raw = (b"From: Attacker <attacker@evil.test>\r\n"
               + dual.encode("utf-8") + b"\r\n"
               b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 15:00:00 +0000\r\n"
               + ("Subject: [%s] reply target probe\r\n" % case_id).encode()
               + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
               + ("X-Case-ID: %s\r\n" % case_id).encode()
               + b"\r\nPlease confirm the payment.\r\n")
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
            sent = {"accepted": False}
        print(name, "->", (sent.get("reply") or "")[:40], flush=True)
        time.sleep(1.5)


if __name__ == "__main__":
    main()
