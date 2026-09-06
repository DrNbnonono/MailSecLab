#!/usr/bin/env python3
"""I1: send a message via BDAT (CHUNKING), payload may contain embedded
end-of-data separators. usage: send_bdat.py HOST PORT PAYLOAD_FILE CASE
"""
import socket, sys

host, port, path, case = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
payload = open(path, "rb").read()

s = socket.create_connection((host, port), timeout=60)
f = s.makefile("rb")
def rl():
    while True:
        l = f.readline().decode(errors="replace").rstrip()
        if len(l) < 4 or l[3] != "-":
            return l
rl()
s.sendall(b"EHLO client.lab.test\r\n")
caps = []
while True:
    l = f.readline().decode(errors="replace").rstrip()
    caps.append(l)
    if len(l) < 4 or l[3] != "-":
        break
chunking = any("CHUNKING" in c.upper() for c in caps)
print(f"CHUNKING={chunking}")
s.sendall(f"MAIL FROM:<alice@sender.lab.test>\r\n".encode()); rl()
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); rl()
s.sendall(b"BDAT %d LAST\r\n" % len(payload))
s.sendall(payload)
print("BDAT_REPLY:", rl())
s.sendall(b"QUIT\r\n")
