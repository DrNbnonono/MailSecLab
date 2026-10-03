import imaplib

m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
for case in ("gf-obs-from-fresh-0002", "gf-obs-from-guided.dup-line-0005"):
    typ, data = m.uid("SEARCH", "TEXT", '"%s"' % case)
    print(case, "TEXT uids:", data[0].decode())
    uids = data[0].split()
    if uids:
        typ, msg = m.uid("FETCH", uids[-1].decode(), "(ENVELOPE)")
        for item in msg:
            if isinstance(item, tuple):
                print("   env:", item[0][:160])
                break
m.logout()
