"""Rescan the saved I2 messages after H_SOURCE_IP actually registers."""
import json
import subprocess
from pathlib import Path

root = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
summary_path = root / "i2" / "summary.json"
summary = json.loads(summary_path.read_text(encoding="utf-8"))
by_mode = {row["mode"]: row for row in summary}

for mode in ("plain", "consistent", "inconsistent"):
    for label in ("input", "stored"):
        target = f"/evidence/w1-20261001a/i2/{mode}/{label}.eml"
        proc = subprocess.run(
            ["docker", "exec", "msl-rspamd", "rspamc", "--json", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        text = proc.stdout.decode("utf-8", "replace")
        out = root / "i2" / mode / f"rspamd-{label}.json"
        out.write_text(text or proc.stderr.decode("utf-8", "replace"), encoding="utf-8")
        payload = json.loads(text)
        symbol = (payload.get("symbols") or {}).get("H_SOURCE_IP") or {}
        by_mode[mode]["rspamd"][label] = {
            "status": "none",
            "action": payload.get("action"),
            "score": payload.get("score"),
            "source": symbol.get("options") or [],
            "rescan": "after H_SOURCE_IP registration; same stored bytes",
        }
        print(mode, label, symbol.get("options"))

summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
