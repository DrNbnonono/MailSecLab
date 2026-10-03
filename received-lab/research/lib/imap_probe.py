"""B-line: Dovecot server-side identity consumers - ENVELOPE instance
selection on duplicate From, and the SEARCH matching matrix (ASCII + UTF-8).
Writes exec/imap-probe.json and prints a compact summary.
"""
import imaplib
import json
import socket

OUT = "/evidence/w2-20261002a/exec/imap-probe.json"


def main() -> None:
    m = imaplib.IMAP4("msl-dovecot", 143)
    m.login("bob", "lab-bob")
    m.select("INBOX", readonly=True)
    envelopes = {}
    for uid in ("3", "27", "22", "32"):
        typ, msg = m.fetch(uid, "(ENVELOPE)")
        envelopes[uid] = repr(msg[0]) if msg and msg[0] else "nil"
    searches = {}
    for label, crit in [
        ("header-from-attacker", ("HEADER", "FROM", '"attacker"')),
        ("header-from-author", ("HEADER", "FROM", '"author"')),
        ("header-from-extra", ("HEADER", "FROM", '"extra"')),
        ("from-key-attacker", ("FROM", '"attacker"')),
        ("header-from-alabel", ("HEADER", "FROM", '"xn--mnchen-3ya"')),
        ("header-from-spoofed", ("HEADER", "FROM", '"Spoofed"')),
        ("header-xcaseid-z14", ("HEADER", "X-CASE-ID", '"z14"')),
    ]:
        typ, data = m.search(None, *crit)
        searches[label] = data[0].decode()
    m.logout()

    raw_out = {}
    s = socket.create_connection(("msl-dovecot", 143))
    f = s.makefile("rb")
    f.readline()

    def raw(tag: str, payload: bytes) -> str:
        s.sendall(tag.encode() + b" " + payload + b"\r\n")
        chunks = []
        while True:
            line = f.readline()
            chunks.append(line)
            if line.startswith(tag.encode() + b" "):
                break
        return b"".join(chunks).decode("utf-8", "replace").strip()

    raw_out["login"] = raw("a1", b"LOGIN bob lab-bob").splitlines()[-1]
    raw_out["select"] = raw("a2", b"SELECT INBOX").splitlines()[0]
    needle = "münchen".encode("utf-8")
    raw_out["search-charset-utf8-ulabel"] = raw("a3", b'SEARCH CHARSET UTF-8 HEADER FROM "' + needle + b'"')
    raw_out["search-no-charset-ulabel"] = raw("a4", b'SEARCH HEADER FROM "' + needle + b'"')
    s.close()

    result = {"envelopes": envelopes, "searches": searches, "raw": raw_out}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
    for uid, text in envelopes.items():
        frag = text[80:400] if len(text) > 80 else text
        print("ENVELOPE", uid, frag)
    for label, hits in searches.items():
        print("SEARCH", label, "->", hits)
    for label, text in raw_out.items():
        print("RAW", label, "->", text.replace("\r\n", " | "))


if __name__ == "__main__":
    main()
