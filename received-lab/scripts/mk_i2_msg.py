#!/usr/bin/env python3
"""I2 message builder: Received chain consistency vs rspamd.
usage: mk_i2_msg.py OUT CASE MODE (consistent|inconsistent|plain)
Forged chain is crafted so each 'by' matches the NEXT header's 'from',
and the LAST forged hop's 'by' equals the client's real EHLO/IP so it
joins seamlessly onto postfix1's genuine header after relay.
"""
import sys

out, case, mode = sys.argv[1], sys.argv[2], sys.argv[3]
CLIENT_HOST = "client.lab.test"
CLIENT_IP = "172.22.0.3"

chain_consistent = [
    "Received: from origin0.spoof.example (192.0.113.65)\r\n"
    "\tby relay1.spoof.example (192.0.113.66); Tue, 1 Jan 2030 00:00:00 +0000",
    "Received: from relay1.spoof.example (192.0.113.66)\r\n"
    f"\tby {CLIENT_HOST} ({CLIENT_IP}); Tue, 1 Jan 2030 00:00:01 +0000",
]
chain_inconsistent = [
    "Received: from mail0.spoof.example (192.0.113.65)\r\n"
    "\tby relay0.spoof.example; Tue, 1 Jan 2030 00:00:00 +0000",
]

if mode == "consistent":
    fakes = chain_consistent
elif mode == "inconsistent":
    fakes = chain_inconsistent
else:
    fakes = []

hdrs = [f"X-Case-ID: {case}"] + fakes + [
    "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
    f"Subject: I2 {mode} {case}", "Message-ID: <i2@sender.lab.test>", "", "body."]
data = ("\r\n".join(hdrs) + "\r\n").encode()
open(out, "wb").write(data)
print(out, len(data), "bytes mode=" + mode)
