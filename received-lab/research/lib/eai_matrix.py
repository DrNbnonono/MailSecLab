"""Route A: EAI / U-label vs A-label identity binding through the auth chain.

Each case is signed once with the w1 key, verified by the four verifiers
(pre-send, file bytes), then sent through msl-auth-postfix so OpenDKIM and
OpenDMARC stamp their own Authentication-Results, then fetched back over IMAP
with the ENVELOPE response preserved. DNS query attribution comes from the
msl-dns log; per-case UTC timestamps are recorded for correlation.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "eai"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
EVIDENCE = "/evidence/w2-20261002a/eai"

H_NAMES = ["from", "to", "date", "subject", "message-id"]
VICTIM_ALABEL = "xn--mnchen-3ya.lab.test"          # A-label of münchen.lab.test
VICTIM_ULABEL = "münchen.lab.test"                   # kept as a Python str; encoded per use

CASES = [
    {"name": "a0-ascii-control", "from": "From: Author <author@lab.test>", "d": "lab.test", "s": "cal"},
    {"name": "a0-utf8-display", "from": "From: 作者 <author@lab.test>", "d": "lab.test", "s": "cal"},
    {"name": "a0-utf8-fieldname", "from": "From: Author <author@lab.test>", "d": "lab.test", "s": "cal",
     "post_sign_insert": b"X-\xc3\x9cnknow: one\r\n"},
    {"name": "a1-ulabel-from", "from": f"From: Author <author@{VICTIM_ULABEL}>", "d": "lab.test", "s": "cal"},
    {"name": "a1-ulabel-from-idnd", "from": f"From: Author <author@{VICTIM_ULABEL}>", "d": VICTIM_ALABEL, "s": "cal"},
    {"name": "a1-alabel-from-idnd", "from": f"From: Author <author@{VICTIM_ALABEL}>", "d": VICTIM_ALABEL, "s": "cal"},
    {"name": "a1-2047-display", "from": "From: =?utf-8?B?5L2g5aW9?= <author@lab.test>", "d": "lab.test", "s": "cal"},
]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def build(case: dict) -> bytes:
    case_id = "eai-" + case["name"]
    headers = [
        case["from"].encode("utf-8"),
        b"To: recipient@receiver.test",
        b"Date: Fri, 2 Oct 2026 12:00:00 +0000",
        b"Subject: eai binding probe",
        f"Message-ID: <{case_id}@lab.test>".encode(),
        f"X-Case-ID: {case_id}".encode(),
    ]
    raw = b"\r\n".join(headers) + b"\r\n\r\nControlled research body.\r\nCase: " + case_id.encode() + b"\r\n"
    return raw


def insert_after_signature(raw: bytes, extra: bytes) -> bytes:
    info = structure.inspect(raw)
    sig = next(field for field in info["fields"] if field["name"] == "dkim-signature")
    return raw[:sig["end"]] + extra + raw[sig["end"]:]


FETCH_SCRIPT = r'''
import imaplib, json, sys
case = sys.argv[1]
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, data = m.search(None, "ALL")
out = {"found": False}
for item in reversed(data[0].split()):
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = msg[0][1] if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, env = m.fetch(item, "(ENVELOPE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SENDER REPLY-TO AUTHENTICATION-RESULTS)])")
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/eai/{case}.stored.eml", "wb").write(raw)
    out = {
        "found": True,
        "uid": item.decode(),
        "bytes": len(raw),
        "envelope_raw": repr(env),
        "size": repr(full),
    }
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 12, delay: float = 4.0) -> dict:
    for _ in range(tries):
        code, out, err = sh(
            ["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
            timeout=60,
            stdin=FETCH_SCRIPT.encode(),
        )
        try:
            result = json.loads(out)
        except json.JSONDecodeError:
            result = {"found": False, "raw": (out or err)[-300:]}
        if result.get("found"):
            return result
        time.sleep(delay)
    return result


def auth_results(raw: bytes) -> list[str]:
    lines = []
    for line in raw.split(b"\r\n"):
        if line.lower().startswith(b"authentication-results"):
            lines.append(line.decode("utf-8", "replace"))
    return lines


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    started = now()
    for case in CASES:
        name = case["name"]
        case_id = "eai-" + name
        raw = build(case)
        info = structure.inspect(raw)
        if info["issues"]:
            raise SystemExit(f"{name}: structure issues before signing: {info['issues']}")
        signed, meta = reference.sign(
            raw, KEY, H_NAMES, mode="relaxed",
            domain=case["d"], selector=case["s"],
        )
        if case.get("post_sign_insert"):
            signed = insert_after_signature(signed, case["post_sign_insert"])
        path = STAGE / f"{name}.eml"
        path.write_bytes(signed)
        sig_check = structure.inspect(signed)
        t_verify = now()
        verdicts = verify_file(f"{EVIDENCE}/{name}.eml")
        t_send = now()
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{name}.eml",
            "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-400:]}
        stored = fetch_stored(case_id)
        stored_raw = (STAGE / f"{name}.stored.eml").read_bytes() if (STAGE / f"{name}.stored.eml").exists() else b""
        stored_info = structure.inspect(stored_raw) if stored_raw else {"issues": ["not-delivered"]}
        row = {
            "case": name,
            "case_id": case_id,
            "from_header": case["from"],
            "dkim_d": case["d"],
            "dkim_s": case["s"],
            "post_sign_insert": bool(case.get("post_sign_insert")),
            "sent_sha256": sha256_bytes(signed),
            "sent_bytes": len(signed),
            "pre_structure": {"issues": info["issues"], "syntax": sorted({f["syntax"] for f in sig_check["fields"]})},
            "stored_structure": {"issues": stored_info.get("issues"), "syntax": sorted({f["syntax"] for f in stored_info.get("fields", [])})},
            "t_verify": t_verify,
            "t_send": t_send,
            "verifiers": {k: v.get("status") for k, v in verdicts.items()},
            "smtp": sent,
            "stored": stored,
            "authentication_results": auth_results(stored_raw),
            "sign_meta_h": meta.get("h"),
        }
        write_json(STAGE / f"{name}.json", {"row": row, "verifiers": verdicts, "sign_meta": meta})
        rows.append(row)
        print(json.dumps({
            "case": name, "verifiers": row["verifiers"],
            "smtp_reply": (sent.get("reply") or "")[:60],
            "stored_bytes": row["stored"].get("bytes"),
            "ar": row["authentication_results"],
        }, ensure_ascii=False), flush=True)
        time.sleep(6)
    write_json(STAGE / "cases.json", {"started": started, "finished": now(), "rows": rows})
    code, out, err = sh(["docker", "logs", "--timestamps", "--since", started, "msl-dns"], timeout=60)
    (STAGE / "dns-window.log").write_text(out, encoding="utf-8")
    print("dns-window lines:", len(out.splitlines()))


if __name__ == "__main__":
    main()
