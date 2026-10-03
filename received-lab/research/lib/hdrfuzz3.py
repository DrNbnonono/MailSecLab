"""hdrfuzz3: thousand-scale sweep over the identity-field half that the fast
pipeline has not covered - forged-AR forms (survival is now a first-class
outcome), Reply-To / Sender grammar (Dovecot ENVELOPE slots as oracle), plus
a reduced From pool that generates the known divergence families.

Parallel-safe: unique case ids per seed; rspamd log matched by Message-ID.
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "hdrfuzz3"
EVIDENCE = "/evidence/w2-20261002a/hdrfuzz3"
VICTIM = "xn--mnchen-3ya.lab.test"
NFC = "m\u00fcnchen.lab.test"

FROM_POOL = [
    ("angle-ascii", "From: Bank Security <security@lab.test>"),
    ("angle-victim", f"From: Bank Security <security@{VICTIM}>"),
    ("angle-ulabel", f"From: Bank Security <security@{NFC}>"),
    ("group-victim", f"From: Bank: security@{VICTIM};"),
    ("obs-ascii", "From : Bank Security <security@lab.test>"),
    ("bare-victim", f"From: security@{VICTIM}"),
    ("dl-victim", f"From: Bank Security <security@{VICTIM.replace(VICTIM, '')}x@203.0.113.7>".replace("<x@", "<security@[").replace("@203.0.113.7>", "@[203.0.113.7]>")),
]
AR_FORMS = [
    ("none", None),
    ("foreign-pass", "Authentication-Results: receiver.example; dkim=pass (2048-bit key) header.d=xn--mnchen-3ya.lab.test header.b=ZZFZ1"),
    ("foreign-fail", "Authentication-Results: mx.other.example; dkim=fail (bad signature) header.d=lab.test"),
    ("own-pass", "Authentication-Results: mail.lab.test; dkim=pass header.d=xn--mnchen-3ya.lab.test header.b=ZZFZ2"),
    ("foreign-dmarc", "Authentication-Results: receiver.example; dmarc=pass (p=reject dis=none) header.from=xn--mnchen-3ya.lab.test"),
    ("foreign-obs", "Authentication-Results : receiver.example; spf=pass smtp.mailfrom=xn--mnchen-3ya.lab.test"),
]
REPLYTO_FORMS = [
    ("none", None),
    ("evil", "Reply-To: Reply <reply@evil.test>"),
    ("victim", f"Reply-To: Bank <security@{VICTIM}>"),
    ("obs-evil", "Reply-To : Reply <reply@evil.test>"),
    ("dup-evil-victim", f"Reply-To: Reply <reply@evil.test>\r\nReply-To: Bank <security@{VICTIM}>"),
    ("dup-victim-evil", f"Reply-To: Bank <security@{VICTIM}>\r\nReply-To: Reply <reply@evil.test>"),
]
SENDER_FORMS = [
    ("none", None),
    ("evil", "Sender: Agent <agent@evil.test>"),
    ("victim", f"Sender: Bank <security@{VICTIM}>"),
    ("obs", "Sender : Agent <agent@evil.test>"),
]


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


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
    blob = (msg[0][1] or b"") if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, env = m.fetch(item, "(ENVELOPE)")
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/hdrfuzz3/{case}.stored.eml", "wb").write(raw)
    surv = [l.decode("utf-8", "replace").strip()[:120] for l in raw.split(b"\r\n") if b"receiver.example" in l or b"other.example" in l or b"ZZFZ" in l]
    ars = [l.decode("utf-8", "replace").strip()[:110] for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "ar_surv": surv, "ar": ars, "envelope": repr(env[0])}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 6, delay: float = 0.8):
    last = {"found": False}
    for _ in range(tries):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                          timeout=60, stdin=FETCH_SCRIPT.encode())
        try:
            last = json.loads(out)
        except json.JSONDecodeError:
            last = {"found": False}
        if last.get("found"):
            return last
        time.sleep(delay)
    return last


DMARC_RE = re.compile(r"dmarc=(\w+)")
RSPAMD_DMARC_RE = re.compile(r"(DMARC_POLICY_[A-Z_]+)")


def env_slots(env_repr: str) -> dict:
    return {
        "sender_evil": '"agent" "evil.test"' in env_repr,
        "sender_victim": '"security" "xn--' in env_repr or '"Bank"' in env_repr,
        "reply_evil": '"reply" "evil.test"' in env_repr,
        "reply_victim": ('"security" "xn--' in env_repr.split(")) ((")[2]) if len(env_repr.split(")) ((")) > 2 else False,
    }


def rspamd_dmarc(case_id: str) -> str:
    code, out, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                       f"grep 'id: <{case_id}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
    line = out.strip()
    if not line:
        return "absent"
    m = RSPAMD_DMARC_RE.search(line)
    return m.group(1) if m else "no-dmarc-sym"


def build(case_id: str, from_name: str, from_line: str, ar_name: str, ar_line, rt_name: str, rt_line, sd_name: str, sd_line: str) -> bytes:
    head = b""
    if ar_line:
        head += ar_line.encode("utf-8") + b"\r\n"
    head += from_line.encode("utf-8") + b"\r\n"
    if sd_line:
        head += sd_line.encode("utf-8") + b"\r\n"
    if rt_line:
        head += rt_line.encode("utf-8") + b"\r\n"
    head += (b"To: bob@lab.test\r\n"
             b"Date: Sat, 3 Oct 2026 13:00:00 +0000\r\n"
             b"Subject: hdrfuzz3 probe\r\n"
             + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
             + f"X-Case-ID: {case_id}\r\n".encode())
    return head + b"\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"


def run_chunk(n: int, seed: int) -> None:
    rng = random.Random(seed)
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    t0 = time.time()
    for i in range(n):
        fname, fline = rng.choice(FROM_POOL)
        aname, aline = rng.choice(AR_FORMS)
        rtname, rtline = rng.choice(REPLYTO_FORMS)
        sdname, sdline = rng.choice(SENDER_FORMS)
        case_id = f"h3-{seed}-{i:04d}"
        raw = build(case_id, fname, fline, aname, aline, rtname, rtline, sdname, sdline)
        (STAGE / f"{case_id}.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{case_id}.eml", "--transcript", f"{EVIDENCE}/{case_id}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        ar_text = " ".join(stored.get("ar") or [])
        d = DMARC_RE.search(ar_text)
        row = {
            "case": case_id, "from": fname, "ar_form": aname, "replyto": rtname, "sender": sdname,
            "smtp_code": (sent.get("reply") or "")[:3], "delivered": stored.get("found"),
            "od": d.group(1) if d else "absent",
            "surv": stored.get("ar_surv", []),
            "rspamd": rspamd_dmarc(case_id),
            "env": (stored.get("envelope") or "")[:240],
            "sha256": sha256_bytes(raw),
        }
        rows.append(row)
        if (i + 1) % 25 == 0:
            print(f"seed {seed}: {i+1}/{n} in {time.time()-t0:.0f}s", flush=True)
    (STAGE / f"rows-seed{seed}.json").write_text(json.dumps({"seed": seed, "n": n, "seconds": round(time.time() - t0, 1), "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"seed {seed} DONE {n} in {time.time()-t0:.0f}s", flush=True)


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    seed = int(sys.argv[2])
    run_chunk(n, seed)


if __name__ == "__main__":
    main()
