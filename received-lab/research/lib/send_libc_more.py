"""Resend colon-space From and insert-after From through the libc OpenDKIM."""
import json
import subprocess
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
OUT = RUN / "clients" / "chain-b-libc"
SOURCES = {
    "colon": RUN / "identity/from-colon-space.eml",
    "insert-after": RUN / "causal/cases/from-relaxed-n1-h1-insert-after/mutant.eml",
}

for name, src in SOURCES.items():
    raw = b"X-Case-ID: chain-b-libc-" + name.encode() + b"\r\n" + src.read_bytes()
    (OUT / f"{name}.eml").write_bytes(raw)
    proc = subprocess.run(
        [
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--input", f"/evidence/w1-20261001a/clients/chain-b-libc/{name}.eml",
            "--transcript", f"/evidence/w1-20261001a/clients/chain-b-libc/{name}.smtp.txt",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    print(name, proc.stdout.decode()[:300])

imap = r'''
import imaplib
from pathlib import Path
out = Path("/evidence/w1-20261001a/clients/chain-b-libc")
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX")
typ, data = m.search(None, "ALL")
for item in data[0].split():
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1]
    text = raw.decode("latin1")
    if "chain-b-libc-colon" in text:
        name = "colon"
    elif "chain-b-libc-insert-after" in text:
        name = "insert-after"
    else:
        continue
    (out / f"{name}.stored.eml").write_bytes(raw)
    print(name, len(raw))
m.logout()
'''
subprocess.run(["docker", "exec", "-i", "msl-client", "python3", "-"], input=imap.encode(), check=False)
