import imaplib
from pathlib import Path

out = Path("/evidence/w1-20261001a/clients/chain-a")
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX")
typ, data = m.search(None, "ALL")
for item in data[0].split():
    typ, msg = m.fetch(item, "(BODY.PEEK[])")
    raw = msg[0][1]
    text = raw.decode("latin1")
    if "chain-a-" not in text:
        continue
    name = "legit" if "chain-a-legit" in text else "from-insert-before"
    (out / f"{name}.stored.eml").write_bytes(raw)
    headers = []
    for line in text.split("\r\n\r\n", 1)[0].split("\r\n"):
        low = line.lower()
        if low.startswith(("from:", "to:", "subject:", "authentication-results:", "x-spamd", "x-rspamd", "x-case-id:")):
            headers.append(line)
    (out / f"{name}.headers.txt").write_text("\n".join(headers) + "\n", encoding="utf-8")
    print(name, "bytes", len(raw))
m.logout()
