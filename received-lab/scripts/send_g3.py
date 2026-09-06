#!/usr/bin/env python3
"""G3: send a message with one WSP-variant header line; run inside mail-client.
usage: send_g3.py CASE SERVER PORT HDR_LINE   (HDR_LINE: \t means TAB)"""
import socket, sys

case, server, port, hdrline = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
hdrline = hdrline.replace("\\t", "\t")
msg = (f"X-Case-ID: {case}\r\n{hdrline}\r\nMessage-ID: <g3@sender.lab.test>\r\n\r\nbody.\r\n").encode()
open(f"/results/g-series/logs/{case}.input.eml", "wb").write(msg)
s = socket.create_connection((server, port), timeout=30)
f = s.makefile("rb")
def rl():
    while True:
        l = f.readline().decode(errors="replace").rstrip()
        if len(l) < 4 or l[3] != "-":
            return l
rl(); s.sendall(b"EHLO client.lab.test\r\n"); rl()
s.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n"); rl()
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); rl()
s.sendall(b"DATA\r\n"); rl()
s.sendall(msg + b"\r\n.\r\n")
print("DATA_REPLY:", rl())
s.sendall(b"QUIT\r\n")
