#!/usr/bin/env python3
"""G1 variants: what exactly makes rspamd drop the rest of the header block?
usage: gen_g_variant.py OUT CASE MODE KB
modes (identity headers always AFTER the giant header):
  f1    folded X-Received, 1 x ~KB (long ~897-char continuation lines)
  f1u   UNfolded single-line X-Received, ~KB
  xg    folded X-Giant, ~KB
  rcv   folded real 'Received:', ~KB
  f1s   folded X-Received with SHORT continuation lines, total ~KB
  f1o   folded X-Received, ONE ~897-char continuation line
  f1t   folded X-Received, ONE 100-char continuation line
  f1l   folded X-Received, ONE 5000-char continuation line
  ctrl  no giant header (control)
"""
import os, sys

def folded(name, i, target):
    first = f"{name}: from g{i}.lab.test by g{i}.lab.test; Tue, 1 Jan 2030 00:00:00 +0000\r\n"
    cont = " (" + "A" * 894 + ")\r\n"
    parts, ln = [first], len(first)
    while ln < target:
        parts.append(cont); ln += len(cont)
    return "".join(parts).rstrip("\r\n")

def folded_short(name, i, target):
    first = f"{name}: from g{i}.lab.test by g{i}.lab.test; Tue, 1 Jan 2030 00:00:00 +0000\r\n"
    parts, ln = [first], len(first)
    while ln < target:
        c = " (short continuation " + "B" * 20 + ")\r\n"
        parts.append(c); ln += len(c)
    return "".join(parts).rstrip("\r\n")

def folded_n(name, n, contlen):
    first = f"{name}: from g0.lab.test by g0.lab.test; Tue, 1 Jan 2030 00:00:00 +0000"
    return first + "".join("\r\n (" + "D" * contlen + ")" for _ in range(n))

def folded_one(name, contlen):
    first = f"{name}: from g0.lab.test by g0.lab.test; Tue, 1 Jan 2030 00:00:00 +0000"
    return first + "\r\n (" + "C" * contlen + ")"

out, case, mode = sys.argv[1], sys.argv[2], sys.argv[3]
kb = int(sys.argv[4]) if len(sys.argv) > 4 else 8

giants = {
    "f1":   lambda: [folded("X-Received", 0, kb * 1024)],
    "f1u":  lambda: ["X-Received: " + "A" * (kb * 1024)],
    "xg":   lambda: [folded("X-Giant", 0, kb * 1024)],
    "rcv":  lambda: [folded("Received", 0, kb * 1024)],
    "f1s":  lambda: [folded_short("X-Received", 0, kb * 1024)],
    "f1o":  lambda: [folded_one("X-Received", 897)],
    "f1t":  lambda: [folded_one("X-Received", 100)],
    "f1l":  lambda: [folded_one("X-Received", 5000)],
    "f1n":  lambda: [folded_n("X-Received", int(sys.argv[5]) if len(sys.argv) > 5 else 2, kb)],
    "ctrl": lambda: [],
}
hdrs = [f"X-Case-ID: {case}"] + giants[mode]() + [
    "From: Alice <alice@sender.lab.test>", "To: Bob <bob@receiver.lab.test>",
    f"Subject: G1 variant {case}", "Message-ID: <g@sender.lab.test>", "", "body."]
data = ("\r\n".join(hdrs) + "\r\n").encode()
os.makedirs(out, exist_ok=True)
p = os.path.join(out, case + ".eml")
open(p, "wb").write(data)
print(f"{p} {len(data)} bytes mode={mode} kb={kb}")
