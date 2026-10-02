"""Recount the saved OpenSMTPD loop logs and the newest captured message."""
import json
from pathlib import Path

STAGE = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/osmtpd-loop")


def hops(text: str) -> dict:
    ok = perm = 0
    ok_before = None
    for line in text.splitlines():
        if "mta delivery" not in line:
            continue
        if 'result="Ok"' in line:
            ok += 1
            if ok_before is None and "5.4.6" in text:
                pass
        if 'result="PermFail"' in line and "5.4.6" in line and ok_before is None:
            ok_before = ok
            perm += 1
        elif 'result="PermFail"' in line:
            perm += 1
    return {"ok_deliveries": ok, "ok_before_permfail": ok_before, "permfail": perm}


def received_kinds(text: str) -> dict:
    strict = obs = 0
    newest = None
    # The queue dump may use newlines already.
    for line in text.splitlines():
        raw = line.lstrip()
        low = raw.lower()
        if not low.startswith("received"):
            continue
        rest = raw[8:]
        if rest.startswith(":"):
            strict += 1
            newest = raw[:180]
        elif rest[:1] in (" ", "\t") and ":" in rest[:4]:
            obs += 1
    return {"strict_received": strict, "obs_received": obs, "newest_strict": newest}


rows = []
for label in ("loop-normal", "loop-obs"):
    case = STAGE / label
    a = (case / "a.log").read_text(encoding="utf-8", errors="replace")
    b = (case / "b.log").read_text(encoding="utf-8", errors="replace")
    ha, hb = hops(a), hops(b)
    # Prefer a captured message that still contains the case id and the most Received lines.
    best = None
    for path in (case / "samples").glob("*.txt"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if label not in text and "X-Case-ID" not in text and "origin.example" not in text:
            continue
        info = received_kinds(text)
        info["file"] = path.name
        if best is None or info["strict_received"] + info["obs_received"] > best["strict_received"] + best["obs_received"]:
            best = info
    rows.append({"label": label, "a": ha, "b": hb, "message": best})

(STAGE / "counts.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
print(json.dumps(rows, indent=2))
