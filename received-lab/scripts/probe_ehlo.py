#!/usr/bin/env python3
"""EHLO probe: which SMTP extensions does each MTA advertise?"""
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=15)
f = s.makefile("rb")
def rl():
    while True:
        l = f.readline().decode(errors="replace").rstrip()
        if len(l) < 4 or l[3] != "-":
            return l
rl()
s.sendall(b"EHLO probe.lab.test\r\n")
exts = []
while True:
    l = f.readline().decode(errors="replace").rstrip()
    exts.append(l)
    if len(l) < 4 or l[3] != "-":
        break
s.sendall(b"QUIT\r\n")
for e in exts:
    if any(k in e.upper() for k in ("CHUNKING", "PIPELINING", "SMTPUTF8", "250", "220")):
        print(e)
