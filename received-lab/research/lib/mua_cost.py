"""Bounded local cost of a large header at the MUA.

Hop-count and single-header limits are expected to reject before Dovecot.
A few accepted header blocks are fetched once over IMAP. This is not a flood.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/mua-cost")
EVIDENCE = "/evidence/w1-20261001a/mua-cost"


def sh(args, timeout=120):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def mem() -> dict:
    code, out, _ = sh([
        "docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}",
        "msl-dovecot", "msl-roundcube", "msl-snappymail", "msl-auth-postfix",
    ])
    return {"rc": code, "text": out.strip()}


def received_message(n: int) -> bytes:
    lines = [f"X-Case-ID: mua-received-{n}"]
    for i in range(n):
        lines.append(
            f"Received: from hop{i}.example (hop{i}.example [203.0.113.{i % 200}]) "
            f"by next.example with ESMTP; Thu, 1 Oct 2026 00:00:{i % 60:02d} +0000"
        )
    lines.extend([
        "From: Author <author@lab.test>",
        "To: bob@lab.test",
        "Subject: mua-received",
        "Date: Thu, 1 Oct 2026 00:00:00 +0000",
        "Message-ID: <mua-received@lab.test>",
        "",
        "body",
        "",
    ])
    return ("\r\n".join(lines)).encode()


def xfill_message(total: int) -> bytes:
    # Each field stays under Postfix header_size_limit (102400).
    chunk = "X-Fill: " + ("a" * 60)
    head = [
        f"X-Case-ID: mua-xfill-{total}",
        "From: Author <author@lab.test>",
        "To: bob@lab.test",
        "Subject: mua-xfill",
        "Date: Thu, 1 Oct 2026 00:00:00 +0000",
        "Message-ID: <mua-xfill@lab.test>",
    ]
    blob = "\r\n".join(head).encode() + b"\r\n"
    while len(blob) + len(chunk) + 2 < total:
        blob += chunk.encode() + b"\r\n"
    blob += b"\r\nbody\r\n"
    return blob


def one_header_message(field_len: int) -> bytes:
    value = "b" * field_len
    text = (
        "X-Case-ID: mua-one-header\r\n"
        "From: Author <author@lab.test>\r\n"
        "To: bob@lab.test\r\n"
        "Subject: mua-one\r\n"
        "Date: Thu, 1 Oct 2026 00:00:00 +0000\r\n"
        "Message-ID: <mua-one@lab.test>\r\n"
        f"X-Big: {value}\r\n"
        "\r\nbody\r\n"
    )
    return text.encode()


def send(name: str, raw: bytes) -> dict:
    path = RUN / f"{name}.eml"
    path.write_bytes(raw)
    started = time.perf_counter()
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", "msl-auth-postfix", "--port", "25",
        "--input", f"{EVIDENCE}/{name}.eml",
        "--transcript", f"{EVIDENCE}/{name}.smtp.txt",
    ], timeout=180)
    elapsed = round(time.perf_counter() - started, 3)
    try:
        sent = json.loads(out)
    except json.JSONDecodeError:
        sent = {"accepted": False, "raw": (out or err)[-400:]}
    sent["smtp_seconds"] = elapsed
    sent["input_bytes"] = len(raw)
    return sent


def imap_fetch(token: str) -> dict:
    script = f'''
import imaplib, time
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX")
typ, data = m.search(None, "ALL")
found = None
for item in data[0].split():
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = msg[0][1] if msg and msg[0] else b""
    if b"{token}" in blob:
        found = item
        break
if found is None:
    print("missing")
else:
    t = time.perf_counter()
    typ, msg = m.fetch(found, "(RFC822.SIZE BODY.PEEK[])")
    dt = time.perf_counter() - t
    raw = msg[0][1]
    print(len(raw), round(dt, 3))
m.logout()
'''
    started = time.perf_counter()
    proc = subprocess.run(
        ["docker", "exec", "-i", "msl-client", "python3", "-"],
        input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False,
    )
    text = proc.stdout.decode().strip()
    return {"imap": text, "stderr": proc.stderr.decode()[-200:], "wall": round(time.perf_counter() - started, 3)}


def main() -> None:
    RUN.mkdir(parents=True, exist_ok=True)
    rows = []
    cases = [
        ("received-10", received_message(10)),
        ("received-55", received_message(55)),
        ("one-header-200kb", one_header_message(200_000)),
        ("xfill-1mb", xfill_message(1_000_000)),
        ("xfill-4mb", xfill_message(4_000_000)),
    ]
    before = mem()
    for name, raw in cases:
        print(name, "bytes", len(raw), flush=True)
        row = {"name": name, "before": mem(), "smtp": send(name, raw)}
        time.sleep(2)
        if row["smtp"].get("accepted"):
            row["after"] = mem()
            row["fetch"] = imap_fetch(name)
        rows.append(row)
        print(json.dumps({"name": name, "accepted": row["smtp"].get("accepted"), "reply": row["smtp"].get("reply"), "fetch": row.get("fetch")}), flush=True)
    report = {"before": before, "rows": rows}
    (RUN / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
