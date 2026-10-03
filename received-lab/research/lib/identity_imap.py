import imaplib
from pathlib import Path

out = Path("/evidence/w1-20261001a/identity")
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX")
typ, data = m.search(None, "ALL")
for item in data[0].split():
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1]
    text = raw.decode("latin1")
    if "identity-" not in text:
        continue
    name = None
    for line in text.split("\r\n"):
        if line.startswith("X-Case-ID: identity-"):
            name = line.split("identity-", 1)[1].strip()
            break
    if not name:
        continue
    (out / f"{name}.stored.eml").write_bytes(raw)
    keep = []
    for line in text.split("\r\n\r\n", 1)[0].split("\r\n"):
        low = line.lower()
        if low.startswith(("from", "sender", "reply-to", "resent-from", "authentication-results", "x-case-id", "to:", "subject:")):
            keep.append(line)
    (out / f"{name}.headers.txt").write_text("\n".join(keep) + "\n", encoding="utf-8")
    print(name, "bytes", len(raw))
m.logout()
