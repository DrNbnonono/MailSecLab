"""UDP DNS forwarder probe: logs every query's wire bytes (hex) with the
client address, then forwards to the lab resolver. Single-threaded, serial
queries only - sufficient for milter traffic one message at a time.
"""
import socket
import sys
import time

UPSTREAM = ("10.88.0.53", 53)
LOG = "/evidence/w2-20261002a/qname/fwd.log"


def qname_of(packet: bytes) -> str:
    try:
        i = 12
        labels = []
        while i < len(packet):
            n = packet[i]
            if n == 0:
                break
            labels.append(packet[i + 1:i + 1 + n].hex())
            i += 1 + n
        return ".".join(labels)
    except Exception:
        return "?"


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    with open(LOG, "ab", buffering=0) as fh:
        fh.write(f"# forwarder start {time.strftime('%H:%M:%S')}\n".encode())
        while True:
            data, addr = s.recvfrom(4096)
            fh.write(f"{addr[0]} {time.strftime('%H:%M:%S')} qname_hex_labels={qname_of(data)} wire={data.hex()}\n".encode())
            s.sendto(data, UPSTREAM)
            resp, _ = s.recvfrom(4096)
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()
