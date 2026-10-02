"""Send the fixed week-2 mutants through the three-hop Postfix chain.

The earlier fuzz arm named chain did not open an SMTP session.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from pathlib import Path

from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
STAGE = RUN / "chain-diff"
CASES = {
    "from-insert-before": RUN / "causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml",
    "subject-insert-before": RUN / "causal/cases/subject-relaxed-n1-h1-insert-before/mutant.eml",
    "from-insert-after": RUN / "causal/cases/from-relaxed-n1-h1-insert-after/mutant.eml",
}


def sh(args, timeout=90):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with (STAGE / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def fetch(token, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:18025/api/v1/messages?limit=8", timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            time.sleep(1)
            continue
        for item in data.get("messages") or []:
            mid = item.get("ID")
            if not mid:
                continue
            with urllib.request.urlopen(f"http://127.0.0.1:18025/api/v1/message/{mid}/raw", timeout=30) as resp:
                raw = resp.read()
            if token.encode() in raw:
                return raw, mid
        time.sleep(1)
    return None, None


def main():
    STAGE.mkdir(parents=True, exist_ok=True)
    from research.lib import dockerctl
    log("starting three-hop chain")
    dockerctl.compose("w1-20261001a", ["up", "-d", "dns", "postfix1", "postfix2", "postfix3", "mailpit", "client", "verifiers", "rspamd"], timeout=180)
    deadline = time.time() + 40
    while time.time() < deadline:
        code, out, _ = sh(["docker", "exec", "msl-client", "python3", "-c",
                           "import socket;s=socket.create_connection(('postfix1',25),5);b=s.recv(80);s.close();raise SystemExit(0 if b.startswith(b'220') else 1)"])
        if code == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("postfix1 did not present a banner")
    rows = []
    for name, src in CASES.items():
        raw = b"X-Case-ID: chain-" + name.encode() + b"\r\n" + src.read_bytes()
        dest = STAGE / name
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "input.eml").write_bytes(raw)
        before = verify_file(f"/evidence/w1-20261001a/chain-diff/{name}/input.eml")
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "postfix1", "--port", "25",
            "--input", f"/evidence/w1-20261001a/chain-diff/{name}/input.eml",
            "--transcript", f"/evidence/w1-20261001a/chain-diff/{name}/smtp.txt",
        ], timeout=40)
        sent = json.loads(out) if out.strip().startswith("{") else {"accepted": False, "error": err[-300:]}
        stored, mid = fetch(f"chain-{name}") if sent.get("accepted") else (None, None)
        after = {}
        if stored is not None:
            (dest / "stored.eml").write_bytes(stored)
            verdicts = verify_file(f"/evidence/w1-20261001a/chain-diff/{name}/stored.eml")
            after = {k: v.get("status") for k, v in verdicts.items()}
        row = {
            "case": name,
            "sha256": sha256_bytes(raw),
            "smtp_accepted": bool(sent.get("accepted")),
            "delivery": "delivered" if stored is not None else "pending",
            "mailpit_id": mid,
            "before": {k: v.get("status") for k, v in before.items()},
            "after": after,
        }
        rows.append(row)
        log(f"{name} {row['delivery']} before={row['before']} after={row['after']}")
    same = []
    for row in rows:
        if row["delivery"] == "delivered" and row["before"] == row["after"]:
            same.append(row["case"])
    report = {
        "stage": "chain-diff",
        "passed": all(row["delivery"] == "delivered" for row in rows),
        "rows": rows,
        "unchanged_verdicts": same,
        "note": "This is the SMTP chain the fuzz arm named chain did not run. Added X-Case-ID is outside h=.",
    }
    write_json(STAGE / "summary.json", report)
    lines = ["# SMTP chain differential", ""]
    for row in rows:
        lines.append(f"- {row['case']}: {row['delivery']} before={row['before']} after={row['after']}")
    (STAGE / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"chain-diff passed={report['passed']}")


if __name__ == "__main__":
    main()
