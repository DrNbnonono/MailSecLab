#!/usr/bin/env python3
"""Build the five calibration messages with one fixed key and one wrong key."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import dkim

SELECTOR = b"cal"
DOMAIN = b"lab.test"
HEADERS = [b"from", b"to", b"subject", b"message-id", b"date"]
SIGNED_SUBJECT = b"Subject: calibration legal\r\n"
TAMPERED_SUBJECT = b"Subject: calibration altered\r\n"
BODY = b"\r\ncalibration-body\r\n"
BODY_TAMPERED = b"\r\ncalibration-body-tampered\r\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preimage(case: str, subject: bytes = SIGNED_SUBJECT, body: bytes = BODY) -> bytes:
    headers = [
        f"X-Case-ID: {case}".encode(),
        b"From: Alice <alice@lab.test>",
        b"To: Bob <bob@lab.test>",
        subject.rstrip(b"\r\n"),
        f"Message-ID: <{case}@lab.test>".encode(),
        b"Date: Thu, 01 Oct 2026 12:00:00 +0000",
    ]
    return b"\r\n".join(headers) + b"\r\n" + body


def sign(message: bytes, priv: bytes) -> bytes:
    sig = dkim.sign(
        message,
        SELECTOR,
        DOMAIN,
        priv,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=HEADERS,
    )
    if not sig.endswith(b"\r\n"):
        sig += b"\r\n"
    return sig + message


def main() -> int:
    run_id = os.environ["RUN_ID"]
    root = Path("/evidence") / run_id / "calibrate"
    keys = Path("/evidence") / run_id / "keys"
    root.mkdir(parents=True, exist_ok=True)
    priv = (keys / "priv.pem").read_bytes()
    wrong = (keys / "wrong.pem").read_bytes()
    base = preimage("cal-legal")
    legal = sign(base, priv)
    cases = {
        "legal": legal,
        "header-tamper": legal.replace(SIGNED_SUBJECT, TAMPERED_SUBJECT, 1),
        "body-tamper": legal.replace(BODY, BODY_TAMPERED, 1),
        "wrong-key": sign(preimage("cal-wrong-key"), wrong),
        "unsigned": preimage("cal-unsigned"),
    }
    lf = legal.replace(b"\r\n", b"\n")
    cases["legal-lf"] = lf
    manifest = {"canonicalization": "relaxed/relaxed", "selector": "cal", "domain": "lab.test", "cases": {}}
    for name, data in cases.items():
        path = root / f"{name}.eml"
        path.write_bytes(data)
        manifest["cases"][name] = {
            "path": str(path),
            "sha256": sha256(data),
            "bytes": len(data),
            "gate": name != "legal-lf",
        }
    pre_path = root / "preimage.eml"
    pre_path.write_bytes(base)
    manifest["preimage"] = {"path": str(pre_path), "sha256": sha256(base), "bytes": len(base)}
    if SIGNED_SUBJECT not in legal or legal.count(SIGNED_SUBJECT) != 1:
        raise SystemExit("legal message does not contain exactly one signed subject")
    if TAMPERED_SUBJECT not in cases["header-tamper"]:
        raise SystemExit("header tamper did not apply")
    if cases["header-tamper"] == legal or cases["body-tamper"] == legal:
        raise SystemExit("tamper was a no-op")
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": sorted(cases)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
