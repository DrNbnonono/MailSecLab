#!/usr/bin/env python3
"""Stage-2 surgery control letters (Step 6.1).

One N=1 letter per relay target, rcpt=capture@lab.test, unique X-Case-ID per
target. Verifies the three capture routes (exim -> msl-mailpit:1025,
opensmtpd -> msl-mailpit:1025, auth-postfix transport_maps capture@) by
fetching the archived raw back from the mailpit API.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

STAGE = "/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz/surgery"
EV_STAGE = "/evidence/w4-20261003a/gramfuzz/surgery"

# target -> (server, port); exim resolved from the container's research-net IP
# exactly like diffrun.load_config() does (dual-homed container, name would be
# ambiguous from some peers).
def exim_ip() -> str:
    out = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", "exim"],
        capture_output=True, text=True, check=True).stdout
    addrs = [a for a in out.split() if a]
    research = [a for a in addrs if a.startswith("10.88.")]
    return research[0] if research else addrs[0]


TARGETS = {
    "postfix": ("msl-auth-postfix", 25),
    "exim": (exim_ip(), 25),
    "osmtpd": ("opensmtpd", 25),
}

FETCH = """
import json, sys, time, urllib.request
case_id, out_path = sys.argv[1], sys.argv[2]
for _ in range(10):
    try:
        r = urllib.request.urlopen(
            "http://msl-mailpit:8025/api/v1/messages?limit=50", timeout=5)
        hits = [m for m in json.loads(r.read()).get("messages", [])
                if case_id in (m.get("Subject") or "")]
        if hits:
            newest = max(hits, key=lambda m: m.get("Created") or "")
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw"
                % newest["ID"], timeout=5).read()
            open(out_path, "wb").write(raw)
            print("OK", len(raw))
            sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
"""


def build_raw(case_id: str) -> bytes:
    head = (b"Received: from ctrl0.lab.test (ctrl0.lab.test [203.0.113.7]) "
            b"by ctrl1.lab.test with ESMTP id CTL1; "
            b"Sat, 3 Oct 2026 10:45:00 +0000\r\n")
    lines = [
        "From: Bank Security <security@bank.test>",
        "To: capture@lab.test",
        "Date: Sat, 3 Oct 2026 10:45:00 +0000",
        "Subject: %s" % case_id,
        "Message-ID: <%s@lab.test>" % case_id,
        "X-Case-ID: %s" % case_id,
        "",
        "Surgery control letter.",
    ]
    return head + ("\r\n".join(lines) + "\r\n").encode()


def sh(args, stdin=None, timeout=90):
    p = subprocess.run(args, capture_output=True, input=stdin, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def main() -> int:
    ok = True
    for target, (server, port) in TARGETS.items():
        case = "gf-surgery-ctl-%s" % target
        raw = build_raw(case)
        eml = "%s/%s.eml" % (STAGE, case)
        with open(eml, "wb") as fh:
            fh.write(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3",
            "/opt/research/lib/smtp_send.py",
            "--server", server, "--port", str(port),
            "--mail-from", "alice@lab.test", "--rcpt-to", "capture@lab.test",
            "--input", "%s/%s.eml" % (EV_STAGE, case),
            "--transcript", "%s/%s.smtp.txt" % (EV_STAGE, case),
        ])
        print("[%s] smtp_send rc=%d out=%s err=%s" % (target, code, out.strip(), err.strip()))
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {}
        stored = None
        for _ in range(3):
            code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                               case, "%s/%s.stored.raw" % (EV_STAGE, case)],
                              stdin=FETCH.encode())
            if out.strip().startswith("OK"):
                stored = out.strip()
                break
            time.sleep(1)
        status = stored or "MISS"
        print("[%s] fetch=%s smtp_reply=%s" % (target, status, sent.get("reply", "?")[:60]))
        if not (stored and sent.get("accepted")):
            ok = False
    print("CONTROL", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
