#!/usr/bin/env python3
"""Send a message with injected headers through the lab relay chain.

Two modes:
  generation (default) -- build the message from --style/-n/--header-name etc.
  corpus (--input-file PATH) -- send those exact bytes as DATA unchanged
        (RFC 5321 dot-stuffing only); the case id is read from the file's
        X-Case-ID header so input bytes and tracking id can never diverge.

Styles (--style):
  line    N lines of --header-name (default; classic forged Received)
  resent  N Resent-* blocks (Resent-Date/From/To/Message-ID per block)
  arc     N ARC-style triplets (3 headers per hop, as a forwarding MTA would add)
  folded  N giant folded Received headers of ~--fold-kb KB each
--extra-count M adds M additional lines of --extra-name (any style).
"""
import argparse
import socket
import sys
import uuid
from datetime import datetime, timedelta

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--number", type=int, default=0,
                    help="number of injected units (lines / blocks / triplets / folded headers)")
parser.add_argument("--server", default="postfix1")
parser.add_argument("--port", type=int, default=25)
parser.add_argument("--style", choices=["line", "resent", "arc", "folded"], default="line")
parser.add_argument("--header-name", default="Received",
                    help="field name used by the line style (Received, X-Received, rEcEiVeD, 'Received ', ...)")
parser.add_argument("--fold-kb", type=int, default=90,
                    help="approximate size in KB of each folded Received header (folded style)")
parser.add_argument("--extra-count", type=int, default=0,
                    help="number of extra --extra-name lines to append after the main injection")
parser.add_argument("--extra-name", default="X-Received")
parser.add_argument("--input-file", default=None,
                    help="send these exact bytes as DATA; X-Case-ID is read from the file")
parser.add_argument("--case-id", default=None,
                    help="unique case id used in Subject / X-Case-ID / Message-ID for tracking")
parser.add_argument("--from", dest="sender", default="alice@sender.lab.test")
parser.add_argument("--to", dest="rcpt", default="bob@receiver.lab.test")
args = parser.parse_args()

if args.input_file:
    with open(args.input_file, "rb") as f:
        payload = f.read()
    case = None
    for ln in payload.split(b"\r\n\r\n", 1)[0].split(b"\r\n"):
        if ln.startswith(b"X-Case-ID: "):
            case = ln[len(b"X-Case-ID: "):].decode(errors="replace").strip()
            break
    if not case:
        sys.exit("input file has no X-Case-ID header")
else:
    case = args.case_id or ("T" + uuid.uuid4().hex[:8])
    subject = f"[{case}] received-experiment"

    base = datetime.now()

    def ts(i):
        return (base - timedelta(seconds=i + 1)).strftime("%a, %d %b %Y %H:%M:%S +0800")

    fake = []
    if args.style == "line":
        for i in range(args.number):
            fake.append(
                f"{args.header_name}: from fake{i:03d}.lab.test "
                f"by fake{(i + 1) % 1000:03d}.lab.test "
                f"with ESMTP id {case}-{i:03d}; {ts(i)}"
            )
    elif args.style == "resent":
        for i in range(args.number):
            fake += [
                f"Resent-Date: {ts(i)}",
                "Resent-From: Alice <alice@sender.lab.test>",
                f"Resent-To: Bob <bob@receiver.lab.test>",
                f"Resent-Message-ID: <resent-{case}-{i:04d}@sender.lab.test>",
            ]
    elif args.style == "arc":
        for i in range(args.number):
            fake += [
                f"ARC-Authentication-Results: i={i + 1}; mx{i:03d}.forwarder.lab.test; "
                f"spf=pass smtp.mailfrom=alice@sender.lab.test",
                f"ARC-Message-Signature: i={i + 1}; a=rsa-sha256; d=forwarder{i:03d}.lab.test; s=s1; "
                f"bh={'B' * 52}; b={'C' * 60}",
                f"ARC-Seal: i={i + 1}; a=rsa-sha256; d=forwarder{i:03d}.lab.test; s=s1; "
                f"t={int(base.timestamp()) - i}; b={'D' * 60}",
            ]
    elif args.style == "folded":
        for i in range(args.number):
            target = args.fold_kb * 1024
            head = (f"Received: from fold{i:03d}.lab.test "
                    f"by fold{(i + 1):03d}.lab.test with ESMTP id {case}-FOLD{i:03d};")
            first = f"{head}\r\n {ts(i)}"
            cont = " (" + "A" * 894 + ")"
            body_len = len(first) + 2
            parts = [first]
            while body_len < target:
                parts.append(cont)
                body_len += len(cont) + 2
            parts.append(f" {ts(i + 1)}")
            fake.append("\r\n".join(parts))

    for i in range(args.extra_count):
        fake.append(f"{args.extra_name}: extra{i:03d}.lab.test {case}")

    headers = [f"X-Case-ID: {case}"] + fake + [
        f"From: Alice <{args.sender}>",
        f"To: Bob <{args.rcpt}>",
        f"Subject: {subject}",
        f"Message-ID: <{case}@sender.lab.test>",
        "",
        "Received header experiment body.",
    ]
    payload = ("\r\n".join(headers) + "\r\n").encode()

# RFC 5321 dot-stuffing on bytes
stuffed = b"\r\n".join(
    (b"." + line if line.startswith(b".") else line) for line in payload.split(b"\r\n")
)


class Smtp:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=25)
        self.f = self.sock.makefile("rb")

    def reply(self):
        lines = []
        while True:
            line = self.f.readline()
            if not line:
                raise ConnectionError("connection closed by peer")
            line = line.decode(errors="replace").rstrip("\r\n")
            lines.append(line)
            print("< " + line)
            if len(line) < 4 or line[3] != "-":
                break
        return lines

    def cmd(self, c):
        print("> " + c)
        self.sock.sendall((c + "\r\n").encode())
        return self.reply()


print(f"CASE_ID: {case}")
s = Smtp(args.server, args.port)
s.reply()
s.cmd("EHLO client.lab.test")
s.cmd(f"MAIL FROM:<{args.sender}>")
s.cmd(f"RCPT TO:<{args.rcpt}>")
print("> DATA")
s.sock.sendall(b"DATA\r\n")
s.reply()
s.sock.sendall(stuffed + b"\r\n.\r\n")
final = s.reply()
first = final[0]
print(f"DATA_REPLY: {first}")
print(f"MESSAGE_BYTES: {len(payload)}")
try:
    s.cmd("QUIT")
except Exception:
    pass
sys.exit(0 if first[:1] == "2" else 3)
