import imaplib
import json
import subprocess
from pathlib import Path

run = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
out = run / "clients" / "chain-a"
out.mkdir(parents=True, exist_ok=True)
sources = {
    "legit": run / "causal/preflight/signed.eml",
    "from-insert-before": run / "causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml",
}
for name, src in sources.items():
    raw = b"X-Case-ID: chain-a-" + name.encode() + b"\r\n" + src.read_bytes()
    path = out / f"{name}.eml"
    path.write_bytes(raw)
    proc = subprocess.run([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", "msl-auth-postfix", "--port", "25",
        "--input", f"/evidence/w1-20261001a/clients/chain-a/{name}.eml",
        "--transcript", f"/evidence/w1-20261001a/clients/chain-a/{name}.smtp.txt",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    print(name, proc.stdout.decode()[:240])

m = imaplib.IMAP4("10.88.0.40", 143)
# This script runs on the host, not in the container. IMAP from WSL to docker bridge may fail.
# Fall back is recorded by the caller.
print("imap-from-host-skipped")
