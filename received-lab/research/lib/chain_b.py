"""Send the chain-A pair through OpenDKIM and OpenDMARC, then dump IMAP copies."""
import imaplib
import json
import subprocess
from pathlib import Path

import sys

RUN = Path("/evidence/w1-20261001a")
LABEL = sys.argv[1] if len(sys.argv) > 1 else "chain-b"
OUT = RUN / "clients" / LABEL
OUT.mkdir(parents=True, exist_ok=True)
SOURCES = {
    "legit": RUN / "causal/preflight/signed.eml",
    "from-insert-before": RUN / "causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml",
}

for name, src in SOURCES.items():
    raw = b"X-Case-ID: " + LABEL.encode() + b"-" + name.encode() + b"\r\n" + src.read_bytes()
    path = OUT / f"{name}.eml"
    path.write_bytes(raw)
    proc = subprocess.run(
        [
            "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--input", f"/evidence/w1-20261001a/clients/{LABEL}/{name}.eml",
            "--transcript", f"/evidence/w1-20261001a/clients/{LABEL}/{name}.smtp.txt",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    print(name, proc.stdout.decode()[:400], proc.stderr.decode()[:200])

m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX")
typ, data = m.search(None, "ALL")
found = []
for item in data[0].split():
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1]
    text = raw.decode("latin1")
    token = LABEL + "-"
    if token not in text:
        continue
    name = "legit" if f"{LABEL}-legit" in text else "from-insert-before"
    (OUT / f"{name}.stored.eml").write_bytes(raw)
    headers = []
    for line in text.split("\r\n\r\n", 1)[0].split("\r\n"):
        low = line.lower()
        if low.startswith((
            "from:", "to:", "subject:", "authentication-results:",
            "dkim-signature:", "received-spf:", "x-case-id:",
        )):
            headers.append(line)
    (OUT / f"{name}.headers.txt").write_text("\n".join(headers) + "\n", encoding="utf-8")
    found.append({"name": name, "bytes": len(raw), "uid": item.decode()})
    print(name, "bytes", len(raw))
m.logout()
(OUT / "imap.json").write_text(json.dumps(found, indent=2) + "\n", encoding="utf-8")
print("imap", json.dumps(found))
