"""hdrfuzz4: EXHAUSTIVE cartesian product of the identity axes.

From pool (7) x AR forms (6) x Reply-To forms (6) x Sender forms (4) = 1008
combinations, complete coverage - no random sampling. Sharded for parallel
workers. Oracles identical to hdrfuzz3 (AR survival, OpenDMARC verdict,
rspamd milter symbol, ENVELOPE). Output: full outcome catalog keyed by combo.
"""
from __future__ import annotations

import itertools
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research.lib.evidence import sha256_bytes
from research.lib.hdrfuzz3 import (AR_FORMS, FROM_POOL, REPLYTO_FORMS,
                                   SENDER_FORMS, DMARC_RE, rspamd_dmarc, sh)

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "hdrfuzz4"
EVIDENCE = "/evidence/w2-20261002a/hdrfuzz4"

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
    open(f"/evidence/w2-20261002a/hdrfuzz4/{case}.stored.eml", "wb").write(raw)
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


def build(case_id: str, from_line: str, ar_line, rt_line, sd_line) -> bytes:
    head = b""
    if ar_line:
        head += ar_line.encode("utf-8") + b"\r\n"
    head += from_line.encode("utf-8") + b"\r\n"
    if sd_line:
        head += sd_line.encode("utf-8") + b"\r\n"
    if rt_line:
        head += rt_line.encode("utf-8") + b"\r\n"
    head += (b"To: bob@lab.test\r\n"
             b"Date: Sat, 3 Oct 2026 14:00:00 +0000\r\n"
             b"Subject: hdrfuzz4 probe\r\n"
             + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
             + f"X-Case-ID: {case_id}\r\n".encode())
    return head + b"\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"


def run_shard(shard: int, nshards: int) -> None:
    combos = list(itertools.product(FROM_POOL, AR_FORMS, REPLYTO_FORMS, SENDER_FORMS))
    mine = [c for i, c in enumerate(combos) if i % nshards == shard]
    rows = []
    t0 = time.time()
    for i, ((fname, fline), (aname, aline), (rtname, rtline), (sdname, sdline)) in enumerate(mine):
        case_id = f"h4-{shard}-{i:04d}"
        raw = build(case_id, fline, aline, rtline, sdline)
        (STAGE / f"{case_id}.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{case_id}.eml",
            "--transcript", f"{EVIDENCE}/{case_id}.smtp.txt",
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
            "surv_n": len(stored.get("ar_surv") or []),
            "rspamd": rspamd_dmarc(case_id),
            "env": (stored.get("envelope") or "")[:240],
            "sha256": sha256_bytes(raw),
        }
        rows.append(row)
        if (i + 1) % 50 == 0:
            print(f"shard {shard}: {i+1}/{len(mine)} in {time.time()-t0:.0f}s", flush=True)
    (STAGE / f"rows-shard{shard}.json").write_text(
        json.dumps({"shard": shard, "n": len(rows), "seconds": round(time.time() - t0, 1), "rows": rows},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"shard {shard} DONE {len(rows)} in {time.time()-t0:.0f}s", flush=True)


def main() -> None:
    shard = int(sys.argv[1])
    nshards = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    STAGE.mkdir(parents=True, exist_ok=True)
    run_shard(shard, nshards)


if __name__ == "__main__":
    main()
