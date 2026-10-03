"""C-line: TRUE misalignment matrix with an independent second-level victim
domain (bank.test, p=reject, own org domain). Fixes the h5 caveat where the
victim was a subdomain of lab.test and everything aligned by org domain.

Key cases: duplicate d= with FIRST=victim (does OpenDKIM's AR report the
victim domain while the key was fetched from the last d=?), trailing-dot and
upper-case d= alignment, plus properly-misaligned controls.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.evidence import sha256_bytes
from research.lib.hdrfuzz3 import sh

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "align2"
EVIDENCE = "/evidence/w2-20261002a/align2"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
H = ["from", "to", "date", "subject", "message-id"]

D_FORMS = [
    ("ctrl-bank", b"d=bank.test;\r\n s=cal"),
    ("mis-lab", b"d=lab.test;\r\n s=cal"),
    ("mis-evil", b"d=evil.test;\r\n s=cal"),
    ("dup-first-bank", b"d=bank.test;\r\n d=evil.test;\r\n s=cal"),
    ("dup-first-evil", b"d=evil.test;\r\n d=bank.test;\r\n s=cal"),
    ("dot-bank", b"d=bank.test.;\r\n s=cal"),
    ("upper-bank", b"d=BANK.TEST;\r\n s=cal"),
]


def sign_custom(raw: bytes, middle_tags: bytes) -> bytes:
    info = structure.require_modern(raw)
    body = reference.canonical_body(raw[info["boundary"] + 4:], "relaxed")
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = (b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; " + middle_tags +
                 b";\r\n h=" + ":".join(H).encode() + b";\r\n bh=" + bh + b"; b=\r\n")
    hashed, _ = reference.hashing_input(raw, signature, H, "relaxed")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b"\r\n"
    return signature + raw


def unfold_ars(raw: bytes):
    lines = raw[:raw.find(b"\r\n\r\n")].split(b"\r\n")
    out = []
    for l in lines:
        if l.startswith((b"	", b" ")):
            if out:
                out[-1] += b" " + l.strip()
        else:
            out.append(l)
    return [l.decode("utf-8", "replace") for l in out if b"Authentication-Results" in l]


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, middle in D_FORMS:
        case_id = "al2-" + name
        raw = (b"From: Bank Security <security@bank.test>\r\n"
               b"To: bob@lab.test\r\n"
               b"Date: Sat, 3 Oct 2026 19:00:00 +0000\r\n"
               + ("Subject: align2 %s\r\n" % name).encode()
               + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
               + ("X-Case-ID: %s\r\n" % case_id).encode()
               + b"\r\nPlease confirm the payment.\r\n")
        signed = sign_custom(raw, middle)
        (STAGE / f"{name}.eml").write_bytes(signed)
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
        time.sleep(2.5)
        code, rout, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-"], timeout=60,
                           stdin=('import imaplib\n'
                                  'm = imaplib.IMAP4("msl-dovecot", 143)\n'
                                  'm.login("bob", "lab-bob")\n'
                                  'm.select("INBOX", readonly=True)\n'
                                  'typ, data = m.search(None, "ALL")\n'
                                  'for item in reversed(data[0].split()):\n'
                                  '    typ, msg = m.fetch(item, "(BODY.PEEK[])")\n'
                                  '    raw = msg[0][1]\n'
                                  '    if b"%s" in raw:\n'
                                  '        open("/evidence/w2-20261002a/align2/%s.stored.eml", "wb").write(raw)\n'
                                  '        break\n'
                                  'm.logout()\n' % (case_id, name)).encode())
        ars = []
        try:
            ars = unfold_ars((STAGE / f"{name}.stored.eml").read_bytes())
        except FileNotFoundError:
            pass
        text = " ".join(ars)
        dk = re.search(r"dkim=(\w+)", text)
        dm = re.search(r"dmarc=(\w+)", text)
        hd = re.search(r"header\.d=([^ \t]+)", text)
        row = {"case": name, "smtp": sent.get("reply"),
               "dkim": dk.group(1) if dk else "absent",
               "header_d": hd.group(1) if hd else "-",
               "dmarc": dm.group(1) if dm else "absent",
               "ar": [a[:120] for a in ars][:3], "sha256": sha256_bytes(signed)}
        rows.append(row)
        print(json.dumps({k: row[k] for k in ("case", "smtp", "dkim", "header_d", "dmarc")}, ensure_ascii=False), flush=True)
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
