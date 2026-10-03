"""Signed-axis probe: one fixed DKIM signature, then the From line is
rewritten into each address form (attacker/replay-capable mutation; the
signature bytes never change). Observes which From instance each file
verifier selects into the hash and what the chain evaluators do.

This is the h= selection matrix over non-standard From forms - untested by
prior campaigns (w1 K-series used plain duplicate/modern forms only).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "sigprobe"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
EVIDENCE = "/evidence/w2-20261002a/sigprobe"
H = ["from", "to", "date", "subject", "message-id"]

FORMS = {
    "ctrl-angle": "From: Bank Security <security@lab.test>",
    "group-one": "From: Bank: security@lab.test;",
    "group-empty": "From: Bank:;",
    "domain-literal": "From: Bank Security <security@[203.0.113.7]>",
    "obs-colon": "From : Bank Security <security@lab.test>",
    "bare": "From: security@lab.test",
    "quoted-local": 'From: Bank Security <"security"@lab.test>',
    "folded-empty-first": "From:\r\n <security@lab.test>",
    "dotless": "From: Bank Security <security@labtest>",
    "upper": "From: Bank Security <security@LAB.TEST>",
    "route-addr": "From: Bank Security <@relay.lab.test:security@lab.test>",
}


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def rewrite_from(raw: bytes, new_from: bytes) -> bytes:
    info = structure.inspect(raw)
    field = next(f for f in info["fields"] if f["name"] == "from")
    return raw[:field["start"]] + new_from + b"\r\n" + raw[field["end"]:]


def build_base(case_id: str) -> bytes:
    headers = [b"From: Bank Security <security@lab.test>", b"To: bob@lab.test",
               b"Date: Sat, 3 Oct 2026 10:00:00 +0000", b"Subject: sigprobe",
               f"Message-ID: <{case_id}@lab.test>".encode(), f"X-Case-ID: {case_id}".encode()]
    return b"\r\n".join(headers) + b"\r\n\r\nbody\r\n"


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, from_line in FORMS.items():
        case_id = "sig-" + name
        base = build_base(case_id)
        signed, meta = reference.sign(base, KEY, H, mode="relaxed", domain="lab.test", selector="cal")
        mutant = rewrite_from(signed, from_line.encode("utf-8"))
        if structure.field_bytes(mutant, "dkim-signature") != structure.field_bytes(signed, "dkim-signature"):
            raise SystemExit(name + ": signature changed")
        (STAGE / f"{name}.eml").write_bytes(mutant)
        verdicts = verify_file(f"{EVIDENCE}/{name}.eml")
        statuses = {k: v.get("status") for k, v in verdicts.items()}
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{name}.eml", "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-150:]}
        time.sleep(1.5)
        code, rout, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                            f"grep 'id: <{case_id}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
        rsp = "absent"
        for sym in ("R_DKIM_ALLOW", "R_DKIM_PERMFAIL", "R_DKIM_REJECT", "R_DKIM_NA", "DMARC_POLICY_REJECT", "DMARC_POLICY_ALLOW"):
            if sym in rout:
                rsp = sym
                break
        row = {"case": name, "from_line": from_line.replace("\r\n", "\\r\\n"),
               "verifiers": statuses, "smtp": sent.get("reply"),
               "rspamd_syms": rsp, "sha256": sha256_bytes(mutant)}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
