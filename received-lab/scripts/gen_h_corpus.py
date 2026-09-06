#!/usr/bin/env python3
"""H-series corpus: forged Received with RFC 5737 PUBLIC source IPs.
usage: gen_h_corpus.py OUT CASE N_FORGED [ip_prefix]
Forged headers placed at TOP of DATA (=> BOTTOM of final chain = chronological
first hops = the position a spoofer would claim as source). Identity headers
AFTER, then body. Public IPs: 192.0.2.x / 198.51.100.x / 203.0.113.x rotating.
"""
import os, sys

out, case, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
prefix = sys.argv[4] if len(sys.argv) > 4 else "192.0.2"
pools = ["192.0.2", "198.51.100", "203.0.113"]
fakes = []
for i in range(n):
    ip = f"{pools[i % 3]}.{10 + (i // 3)}"
    fakes.append(f"Received: from mail{ i }.spoof.example ({ip}) by relay{ i }.spoof.example; "
                 f"Tue, 1 Jan 2030 00:00:0{i % 10} +0000")
hdrs = [f"X-Case-ID: {case}"] + fakes + [
    "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
    f"Subject: H {case}", "Message-ID: <h@sender.lab.test>", "", "body."]
data = ("\r\n".join(hdrs) + "\r\n").encode()
os.makedirs(out, exist_ok=True)
p = os.path.join(out, case + ".eml")
open(p, "wb").write(data)
print(f"{p} {len(data)} bytes n={n} prefix={prefix}")
