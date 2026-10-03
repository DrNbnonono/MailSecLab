"""Uncovered identity fields on one fixed signature, plus a few header-syntax cases.

The DKIM-Signature bytes stay equal to the preflight signature. Each case is
verified, then submitted to the auth Postfix so Dovecot and the clients can
show it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
STAGE = RUN / "identity"
SIGNED = RUN / "causal/preflight/signed.eml"
H = ["from", "to", "date", "subject", "message-id"]
INSERTS = {
    "sender": b"Sender: Agent <agent@list.test>\r\n",
    "reply-to": b"Reply-To: Reply <reply@list.test>\r\n",
    "resent-from": b"Resent-From: Resent <resent@list.test>\r\n",
    "from-colon-space": b"From : Extra <extra@evil.test>\r\n",
    "reply-to-folded": b"Reply-To: Reply\r\n <reply@list.test>\r\n",
}


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def insert_after_signature(raw: bytes, extra: bytes) -> bytes:
    info = structure.inspect(raw)
    sig = next(field for field in info["fields"] if field["name"] == "dkim-signature")
    return raw[:sig["end"]] + extra + raw[sig["end"]:]


def hashed_from(raw: bytes) -> str | None:
    chosen = reference.select(raw, H)
    field = chosen[0]
    if field is None:
        return None
    return raw[field["start"]:field["end"]].decode("latin1")


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    base = SIGNED.read_bytes()
    base_sig = next(
        base[field["start"]:field["end"]]
        for field in structure.inspect(base)["fields"]
        if field["name"] == "dkim-signature"
    )
    rows = []
    for name, extra in INSERTS.items():
        body = insert_after_signature(base, extra)
        body = b"X-Case-ID: identity-" + name.encode() + b"\r\n" + body
        path = STAGE / f"{name}.eml"
        path.write_bytes(body)
        new_sig = next(
            body[field["start"]:field["end"]]
            for field in structure.inspect(body)["fields"]
            if field["name"] == "dkim-signature"
        )
        verdicts = verify_file(f"/evidence/w1-20261001a/identity/{name}.eml")
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--input", f"/evidence/w1-20261001a/identity/{name}.eml",
            "--transcript", f"/evidence/w1-20261001a/identity/{name}.smtp.txt",
        ], timeout=40)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-400:]}
        row = {
            "case": name,
            "sha256": sha256_bytes(body),
            "signature_unchanged": new_sig == base_sig,
            "hashed_from": hashed_from(body),
            "verifiers": {key: value.get("status") for key, value in verdicts.items()},
            "smtp": sent,
        }
        rows.append(row)
        print(json.dumps({"case": name, "sig": row["signature_unchanged"], "verify": row["verifiers"], "smtp": sent.get("reply")}), flush=True)
    write_json(STAGE / "before-delivery.json", rows)


if __name__ == "__main__":
    main()
