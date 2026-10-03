"""hdrfuzz5: the SIGNED axis - first fuzz over the DKIM/DMARC alignment space.

Exhaustive: FROM forms (6) x d= forms (6) x h= (minimal/oversigned) x
post-sign From mutation (unchanged / rewritten-to-attacker) = 144 combos.
Signatures are mathematically valid for the lab key (published for lab.test,
evil.test and the IDN victim domain). Oracles: four file verifiers, OpenDKIM
AR, OpenDMARC AR, rspamd milter, delivery.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.evidence import sha256_bytes
from research.lib.hdrfuzz3 import DMARC_RE, sh

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "hdrfuzz5"
EVIDENCE = "/evidence/w2-20261002a/hdrfuzz5"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
VICTIM = "xn--mnchen-3ya.lab.test"

FROMS = [
    ("angle-ascii", "From: Bank Security <security@lab.test>"),
    ("angle-victim", f"From: Bank Security <security@{VICTIM}>"),
    ("angle-ulabel", f"From: Bank Security <security@m\u00fcnchen.lab.test>"),
    ("group-victim", f"From: Bank: security@{VICTIM};"),
    ("dl-literal", "From: Bank Security <security@[203.0.113.7]>"),
    ("bare-victim", f"From: security@{VICTIM}"),
]
D_FORMS = [
    ("victim", f"d={VICTIM};\r\n s=cal"),
    ("own", "d=lab.test;\r\n s=cal"),
    ("trailing-dot", "d=lab.test.;\r\n s=cal"),
    ("upper", "d=LAB.TEST;\r\n s=CAL"),
    ("fws", "d=lab\r\n\t.test;\r\n s=cal"),
    ("duplicate", "d=lab.test;\r\n d=evil.test;\r\n s=cal"),
]
H_FORMS = [
    ("minimal", ["from", "to", "date", "subject", "message-id"]),
    ("oversign", ["from", "from", "to", "date", "subject", "message-id"]),
]
MUTATIONS = [
    ("unchanged", None),
    ("to-attacker", "From: Attacker <attacker@evil.test>"),
]


def sign_custom(raw: bytes, middle_tags: bytes, names: list[str]) -> bytes:
    info = structure.require_modern(raw)
    body = reference.canonical_body(raw[info["boundary"] + 4:], "relaxed")
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = (b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; " + middle_tags +
                 b";\r\n h=" + ":".join(names).encode() + b";\r\n bh=" + bh + b"; b=\r\n")
    hashed, _ = reference.hashing_input(raw, signature, names, "relaxed")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b"\r\n"
    return signature + raw


def rewrite_from(raw: bytes, new_from: bytes) -> bytes:
    info = structure.inspect(raw)
    field = next(f for f in info["fields"] if f["name"] == "from")
    return raw[:field["start"]] + new_from + b"\r\n" + raw[field["end"]:]


def build(case_id: str, from_line: str) -> bytes:
    return (from_line.encode("utf-8") + b"\r\n"
            b"To: bob@lab.test\r\n"
            b"Date: Sat, 3 Oct 2026 16:00:00 +0000\r\n"
            b"Subject: hdrfuzz5 probe\r\n"
            + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
            + f"X-Case-ID: {case_id}\r\n".encode()
            + b"\r\nPlease confirm the payment.\r\n")


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
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/hdrfuzz5/{case}.stored.eml", "wb").write(raw)
    ars = [l.decode("utf-8", "replace").strip()[:130] for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "ar": ars}
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


def file_verdicts(path_in_container: str) -> dict:
    out = {}
    for tool in ("dkimpy", "perl", "go"):
        code, text, err = sh(["docker", "exec", "msl-verifiers", "python3", "/opt/research/lib/verify_one.py", tool, path_in_container], timeout=40)
        try:
            out[tool] = json.loads(text).get("status")
        except Exception:
            out[tool] = "tool-error"
    return out


def run_shard(shard: int, nshards: int) -> None:
    combos = list(itertools.product(FROMS, D_FORMS, H_FORMS, MUTATIONS))
    mine = [c for i, c in enumerate(combos) if i % nshards == shard]
    rows = []
    t0 = time.time()
    for i, ((fname, fline), (dname, dtags), (hname, names), (mname, mline)) in enumerate(mine):
        case_id = f"h5-{shard}-{i:03d}"
        base = build(case_id, fline)
        try:
            signed = sign_custom(base, dtags.encode("latin1"), names)
        except Exception as exc:
            rows.append({"case": case_id, "from": fname, "d": dname, "h": hname, "mut": mname, "error": str(exc)[:120]})
            continue
        mutant = rewrite_from(signed, mline.encode()) if mline else signed
        (STAGE / f"{case_id}.eml").write_bytes(mutant)
        fv = file_verdicts(f"{EVIDENCE}/{case_id}.eml")
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
        dk = re.search(r"dkim=(\w+)", ar_text)
        rows.append({
            "case": case_id, "from": fname, "d": dname, "h": hname, "mut": mname,
            "smtp_code": (sent.get("reply") or "")[:3], "delivered": stored.get("found"),
            "file": fv, "od_dkim": dk.group(1) if dk else "absent",
            "od": d.group(1) if d else "absent",
            "sha256": sha256_bytes(mutant),
        })
        if (i + 1) % 20 == 0:
            print(f"shard {shard}: {i+1}/{len(mine)} in {time.time()-t0:.0f}s", flush=True)
    (STAGE / f"rows-shard{shard}.json").write_text(
        json.dumps({"shard": shard, "n": len(rows), "seconds": round(time.time() - t0, 1), "rows": rows},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"shard {shard} DONE {len(rows)} in {time.time()-t0:.0f}s", flush=True)


def main() -> None:
    shard = int(sys.argv[1])
    nshards = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    STAGE.mkdir(parents=True, exist_ok=True)
    run_shard(shard, nshards)


if __name__ == "__main__":
    main()
