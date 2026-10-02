"""Keep the first-pass artifacts, then allow calibration and I2 to run again."""
import json
from pathlib import Path

root = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
for src_name, dst_name, note in (
    ("calibrate", "calibrate-rejected-adapter",
     "Rejected: dkimpy/perl/go adapters raised tool-error before the libraries ran. rspamd rows in this directory are from that same pass.\n"),
    ("i2", "i2-rejected-header-order",
     "Rejected: forged Received hops were written oldest-first, so the hop under Postfix was not the client hop. Not a joined-chain result.\n"),
):
    src = root / src_name
    dst = root / dst_name
    if src.exists() and not dst.exists():
        src.rename(dst)
        (dst / "WHY-REJECTED.txt").write_text(note, encoding="utf-8")
gate = root / "gate.json"
if gate.exists():
    gate.unlink()
state_path = root / "state.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
state["done"] = [step for step in state["done"] if step not in ("calibrate", "i2")]
state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
print(state)
