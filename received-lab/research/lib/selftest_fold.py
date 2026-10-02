import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.evidence import perl_feed, sha256_bytes
from lib.foldmsg import build_g4, inspect_message

for n in (1, 50, 100):
    raw = build_g4(n, f"G4-N{n}")
    info = inspect_message(raw, n)
    print(n, info["ok"], info["bytes"], info["x_received"], info["max_line"], info["problems"], max(info["unfolded_lengths"]))

sample = build_g4(1, "G4-N1")
lf = sample.replace(b"\r\n", b"\n")
fed = perl_feed(lf)
print("lf_rewritten", fed != lf, b"\r\n" in fed)
print("crlf_identity", perl_feed(b"A: b\r\n\r\nx\r\n") == b"A: b\r\n\r\nx\r\n")
print("sha", sha256_bytes(fed) != sha256_bytes(lf))
