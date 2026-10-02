#!/bin/sh
docker exec msl-opendkim sh -c 'tr "\0" " " < /proc/1/cmdline; echo'
docker exec msl-opendmarc sh -c 'tr "\0" " " < /proc/1/cmdline; echo'
docker exec msl-client python3 -c 'import socket
for name, port in (("msl-opendkim", 8891), ("msl-opendmarc", 8893)):
    s = socket.create_connection((name, port), 3)
    s.settimeout(1)
    try:
        data = s.recv(8)
    except Exception as exc:
        data = str(exc).encode()
    print(name, port, "connected", data)
    s.close()
'
