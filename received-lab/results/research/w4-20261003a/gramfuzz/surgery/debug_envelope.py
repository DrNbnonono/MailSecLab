import imaplib
import sys

m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, msg = m.uid("FETCH", "2817", "(ENVELOPE)")
print("typ:", typ)
for item in msg:
    print("ITEM type:", type(item))
    if isinstance(item, tuple):
        for sub in item:
            print("  SUB type:", type(sub), repr(sub)[:400])
    else:
        print("  ", repr(item)[:400])
typ, msg2 = m.uid("FETCH", "2817", "(BODY.PEEK[HEADER.FIELDS (FROM)])")
print("--- header fields ---")
print(repr(msg2)[:400])
m.logout()
