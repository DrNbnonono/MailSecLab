"""Recfuzz round 2: per-MTA raw capture + hopcount counting divergence.

Each relay (postfix auth / exim v3 / opensmtpd) delivers DIRECTLY to
msl-mailpit's SMTP (1025). Mailpit stores the raw bytes the relay produced -
no downstream MTA rewrites them. Per variant we observe:
  - transform: preserve / normalize / sink-to-body / drop
  - appended:  relay's own Received line (counted evidence)
  - smtp code: acceptance or 5.4.6 (hopcount trip)

hopcount axis: auth-postfix hopcount_limit=50 (default in this stack);
variants are stacked N=55 near the threshold so undercounting by any relay
shows as 250-where-others-reject or vice versa.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "recfuzz2"
EVIDENCE = "/evidence/w2-20261002a/recfuzz2"

PATHS = {"postfix": ("msl-auth-postfix", 25), "exim": ("10.88.0.4", 25), "osmtpd": ("opensmtpd", 25)}

BASE = "Received: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000"


def stack(n: int, template: str) -> str:
    return "\r\n".join(template.format(n=i, n1=i + 1, ip=i % 200, mm=i % 60) for i in range(n))


VARIANTS = {
    "v00-plain": "Received: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v01-obs-colon": "Received : from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v02-case": "rEcEiVeD: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v03-nocolon": "Received from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v04-8bit-name": "Rece\u00edved: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v05-cfws-name": "Received(Router): from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v06-comment-name": "Rece(c)ived: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v07-tab-name": "Received\t: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
}
N_STACK = 55


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


FETCH_IN_CONTAINER = """
import json, sys, urllib.request
case_id = sys.argv[1]
out_path = sys.argv[2]
for _ in range(8):
    try:
        r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=15", timeout=5)
        data = json.loads(r.read())
        for msg in data.get("messages", []):
            if case_id in (msg.get("Subject") or ""):
                rid = msg["ID"]
                raw = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/message/%s/raw" % rid, timeout=5).read()
                open(out_path, "wb").write(raw)
                print("OK", len(raw))
                sys.exit(0)
    except Exception as e:
        pass
    import time; time.sleep(1.2)
print("MISS")
"""


def mailpit_fetch(case_id: str, out_path: str) -> bytes | None:
    for _ in range(3):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id, out_path],
                          timeout=60, stdin=FETCH_IN_CONTAINER.encode())
        if out.strip().startswith("OK"):
            return Path(out_path.replace("/evidence", "/mnt/e/MailSecLab/received-lab/results/research")).read_bytes() if False else None
        time.sleep(1)
    return None


def rec_facts(raw: bytes, variant_key: str) -> dict:
    i = raw.find(b"\r\n\r\n")
    if i < 0:
        return {"zone_end": -1}
    zone, body = raw[:i], raw[i + 4:]
    lines = zone.split(b"\r\n")
    lower = [l.lower() for l in lines]
    rec_exact = sum(1 for l in lower if l.startswith(b"received:"))
    rec_obs = sum(1 for l in lower if l.startswith(b"received :"))
    rec_case = sum(1 for l in lines if l.lower().startswith(b"received:") and not l.startswith(b"Received:"))
    rec_cfws = sum(1 for l in lines if l.startswith(b"Received("))
    rec_8bit = raw.count("Rece\u00edved:".encode())
    relay_added = sum(1 for k in (b"by msl-auth-postfix", b"by auth-postfix", b"by exim", b"by opensmtpd") for l in lines if k in l)
    body_sink = body[:2000]
    return {
        "rec_exact": rec_exact, "rec_obs": rec_obs, "rec_case": rec_case,
        "rec_cfws": rec_cfws, "rec_8bit_total": rec_8bit,
        "relay_added": relay_added,
        "nocolon_body": body_sink.count(b"Received from"),
        "zone_lines": len(lines),
    }


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for vname, tmpl in VARIANTS.items():
        for mta, (server, port) in PATHS.items():
            case_id = f"rf2-{vname}-{mta}"
            head = stack(N_STACK, tmpl).encode("utf-8")
            raw = (head + b"\r\n"
                   + b"From: Bank Security <security@bank.test>\r\n"
                   + b"To: bob@lab.test\r\n"
                   b"Date: Sat, 3 Oct 2026 23:30:00 +0000\r\n"
                   + ("Subject: %s\r\n" % case_id).encode()
                   + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
                   + ("X-Case-ID: %s\r\n" % case_id).encode()
                   + b"\r\nPlease confirm the payment.\r\n")
            (STAGE / f"{vname}-{mta}.eml").write_bytes(raw)
            code, out, err = sh([
                "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
                "--server", server, "--port", str(port),
                "--mail-from", "alice@lab.test", "--rcpt-to", "capture@lab.test",
                "--input", f"{EVIDENCE}/{vname}-{mta}.eml",
                "--transcript", f"{EVIDENCE}/{vname}-{mta}.smtp.txt",
            ], timeout=90)
            try:
                sent = json.loads(out)
            except json.JSONDecodeError:
                sent = {"accepted": False}
            stored = None
            if sent.get("accepted"):
                raw_path = f"{EVIDENCE}/{vname}-{mta}.stored.raw"
                for _ in range(3):
                    code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id, raw_path],
                                      timeout=60, stdin=FETCH_IN_CONTAINER.encode())
                    if out.strip().startswith("OK"):
                        local = STAGE / f"{vname}-{mta}.stored.raw"
                        if local.exists():
                            stored = local.read_bytes()
                            break
                    time.sleep(1)
            facts = {}
            if stored is not None:
                facts = rec_facts(stored, vname)
            row = {"variant": vname, "mta": mta, "smtp_code": (sent.get("reply") or "")[:3],
                   "smtp": (sent.get("reply") or "")[:50], "captured": stored is not None,
                   "facts": facts, "sha256": sha256_bytes(raw)}
            rows.append(row)
            f = facts or {}
            print(json.dumps({"v": vname, "mta": mta, "code": row["smtp_code"], "cap": row["captured"],
                              "exact": f.get("rec_exact"), "obs": f.get("rec_obs"), "case": f.get("rec_case"),
                              "cfws": f.get("rec_cfws"), "app": f.get("relay_added"),
                              "ncB": f.get("nocolon_body")}, ensure_ascii=False), flush=True)
            time.sleep(0.8)
    (STAGE / "matrix.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
