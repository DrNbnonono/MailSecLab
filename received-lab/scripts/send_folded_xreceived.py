#!/usr/bin/env python3
"""R3: send N folded NON-Received (X-Received) ~90KB headers to a server.
Hopcount-blind byte-growth channel test. Run inside mail-client."""
import socket, sys

n = int(sys.argv[1]); case = sys.argv[2]
server = sys.argv[3] if len(sys.argv) > 3 else "postfix1"

def folded(i):
    first = f"X-Received: from fake{i}.lab.test by fake{i}.lab.test; Tue, 1 Jan 2030 00:00:00 +0000"
    cont = " (" + "A" * 894 + ")"
    parts, ln = [first], len(first)
    while ln < 90000:
        parts.append(cont); ln += len(cont) + 2
    return "".join(parts)

hdrs = [f"X-Case-ID: {case}"] + [folded(i) for i in range(n)] + [
    "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
    f"Subject: R3 {case}", "Message-ID: <r3@sender.lab.test>", "", "body."]
data = ((chr(13)+chr(10)).join(hdrs) + chr(13)+chr(10)).encode()
print(f"MESSAGE_BYTES: {len(data)}", file=sys.stderr)

s = socket.create_connection((server, 25), timeout=300); f = s.makefile("rb")
def rl():
    while True:
        l = f.readline().decode(errors="replace").rstrip()
        if len(l) < 4 or l[3] != "-":
            return l
rl(); s.sendall(b"EHLO client.lab.test\r\n"); rl()
s.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n"); rl()
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); rl()
s.sendall(b"DATA\r\n"); rl()
s.sendall(data + b"\r\n.\r\n")
print("DATA_REPLY:", rl())
