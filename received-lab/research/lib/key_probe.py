"""B-line: revoked/malformed DKIM key-record handling across verifiers.

Selectors published in DNS (all resolve):
- cal    : normal key (control, expect pass)
- rev    : p= empty  (RFC 6376 3.6.1: key revoked, MUST fail)
- nop    : no p= tag at all
- dupp   : p= empty THEN p=<real> (duplicate tag; first-p= verifiers see
           revoked, last-p= verifiers see the real key -> divergence detector)

Messages are correctly signed with the real key, From=our own domain, so the
dkim verdict isolates key-record parsing.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference
from research.lib.evidence import sha256_bytes
from research.lib.hdrfuzz3 import sh

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "keyprobe"
EVIDENCE = "/evidence/w2-20261002a/keyprobe"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
H = ["from", "to", "date", "subject", "message-id"]

CASES = [("k-ctrl-cal", "cal"), ("k-revoked", "rev"), ("k-no-p", "nop"), ("k-dup-p", "dupp")]


def file_verdicts(path_in_container: str) -> dict:
    out = {}
    for tool in ("dkimpy", "perl", "go"):
        code, text, err = sh(["docker", "exec", "msl-verifiers", "python3", "/opt/research/lib/verify_one.py", tool, path_in_container], timeout=40)
        try:
            out[tool] = json.loads(text).get("status")
        except Exception:
            out[tool] = "tool-error"
    return out


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, selector in CASES:
        case_id = "key-" + name
        raw = (b"From: Bank Security <security@lab.test>\r\n"
               b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 18:00:00 +0000\r\n"
               + ("Subject: key probe %s\r\n" % name).encode()
               + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
               + ("X-Case-ID: %s\r\n" % case_id).encode()
               + b"\r\nPlease confirm the payment.\r\n")
        signed, _ = reference.sign(raw, KEY, H, mode="relaxed", domain="lab.test", selector=selector)
        (STAGE / f"{name}.eml").write_bytes(signed)
        fv = file_verdicts(f"{EVIDENCE}/{name}.eml")
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
        time.sleep(1.5)
        code, rout, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                            f"grep 'id: <{case_id}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
        rsp = [s for s in ("R_DKIM_ALLOW", "R_DKIM_PERMFAIL", "R_DKIM_REJECT", "R_DKIM_NA") if s in rout]
        row = {"case": name, "selector": selector, "file": fv, "smtp": sent.get("reply"),
               "rspamd": rsp[:1], "sha256": sha256_bytes(signed)}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
