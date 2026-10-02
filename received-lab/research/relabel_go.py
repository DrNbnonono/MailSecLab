"""Relabel go-msgauth from the stderr already stored for this run."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.bootstrap import gate, write_record
from lib.verify_one import classify_text

root = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
path = root / "calibrate" / "results.json"
results = json.loads(path.read_text(encoding="utf-8"))
for row in results:
    go = row["verifiers"]["go"]
    text = (go.get("stdout") or "") + "\n" + (go.get("stderr") or "")
    go["status_before_relabel"] = go.get("status")
    go["status"] = classify_text("go", text, int(go.get("exit_code") or 0))
    if row["case"] == "unsigned":
        dk = row["verifiers"]["dkimpy"]
        dk["status_before_relabel"] = dk.get("status")
        dk["status"] = "none"
        dk["status_note"] = "dkim.verify returned false; the message has no DKIM-Signature header"
path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
report = gate(root)
write_record(root, report)
print(json.dumps(report, indent=2))
