#!/usr/bin/env python3
"""I1b/I2: send raw bytes via DATA with NO dot-stuffing and NO normalization.
The file bytes are sent verbatim after DATA; whatever the server does with
embedded separators is up to the server. Reads and prints all traffic.
usage: send_raw_data.py HOST PORT FILE EHLO_NAME
"""
import socket, sys, time

host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ehlo = sys.argv[4] if len(sys.argv) > 4 else "client.lab.test"
data = open(path, "rb").read()

s = socket.create_connection((host, port), timeout=60)
f = s.makefile("rb")
def rl():
    while True:
        try:
            l = f.readline().decode(errors="replace").rstrip()
        except Exception:
            return ""
        if len(l) < 4 or l[3] != "-":
            return l
rl()
s.sendall(f"EHLO {ehlo}\r\n".encode())
while True:
    l = f.readline().decode(errors="replace").rstrip()
    if len(l) < 4 or l[3] != "-":
        break
s.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n"); print("<", rl())
s.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n"); print("<", rl())
s.sendall(b"DATA\r\n"); print("<", rl())
s.sendall(data)
s.settimeout(6)
# drain all server responses (may include several message acceptances)
end = time.time() + 6
while time.time() < end:
    try:
        l = f.readline().decode(errors="replace").rstrip()
        if not l:
            break
        print("<", l)
    except socket.timeout:
        break
s.close()
