#!/usr/bin/env python3
"""SMTP DATA from inside the client container. Transcript omits the payload."""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys


def read_reply(fh) -> bytes:
    lines = []
    while True:
        line = fh.readline()
        if not line:
            break
        lines.append(line)
        if len(line) >= 4 and line[3:4] == b" ":
            break
    return b"".join(lines)


def dotstuff(data: bytes) -> bytes:
    lines = data.split(b"\r\n")
    # split drops the pairing; a trailing CRLF yields a final empty item.
    stuffed = []
    for i, line in enumerate(lines):
        if line.startswith(b"."):
            line = b"." + line
        stuffed.append(line)
    return b"\r\n".join(stuffed)


def local_ip(server: str, port: int) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((server, port))
        return probe.getsockname()[0]
    finally:
        probe.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=25)
    ap.add_argument("--ehlo", default="client.lab.test")
    ap.add_argument("--mail-from", default="alice@lab.test")
    ap.add_argument("--rcpt-to", default="bob@lab.test")
    ap.add_argument("--input", required=True)
    ap.add_argument("--transcript", required=True)
    args = ap.parse_args()

    payload = open(args.input, "rb").read()
    digest = hashlib.sha256(payload).hexdigest()
    ip = local_ip(args.server, args.port)
    transcript = [f"CLIENT_IP {ip}", f"PAYLOAD_SHA256 {digest}", f"PAYLOAD_BYTES {len(payload)}"]

    sock = socket.create_connection((args.server, args.port), timeout=300)
    fh = sock.makefile("rb")
    try:
        banner = read_reply(fh)
        transcript.append("S " + banner.decode("utf-8", "replace").replace("\r\n", " | "))
        def cmd(line: str) -> bytes:
            transcript.append("C " + line)
            sock.sendall((line + "\r\n").encode())
            reply = read_reply(fh)
            transcript.append("S " + reply.decode("utf-8", "replace").replace("\r\n", " | "))
            return reply

        ehlo = cmd(f"EHLO {args.ehlo}")
        mail = cmd(f"MAIL FROM:<{args.mail_from}>")
        rcpt = cmd(f"RCPT TO:<{args.rcpt_to}>")
        data = cmd("DATA")
        final = data
        if data.startswith(b"354"):
            blob = dotstuff(payload)
            if not blob.endswith(b"\r\n"):
                blob += b"\r\n"
            sock.sendall(blob + b".\r\n")
            final = read_reply(fh)
            transcript.append("S " + final.decode("utf-8", "replace").replace("\r\n", " | "))
            cmd("QUIT")
    finally:
        sock.close()
        open(args.transcript, "w", encoding="utf-8").write("\n".join(transcript) + "\n")

    text = final.decode("utf-8", "replace").strip()
    queued = ""
    marker = "queued as "
    if marker in text:
        queued = text.split(marker, 1)[1].split()[0].strip()
    print(json.dumps({
        "client_ip": ip,
        "reply": text,
        "queued_id": queued,
        "bytes": len(payload),
        "sha256": digest,
        "accepted": text.startswith("250"),
        "banner_ok": banner.startswith(b"220"),
        "ehlo_ok": ehlo.startswith(b"250"),
        "mail_ok": mail.startswith(b"250"),
        "rcpt_ok": rcpt.startswith(b"250"),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
