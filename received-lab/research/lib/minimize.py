"""Rank week-4 splits and check that one edit is enough to keep the split.

Each saved mutant already changes one byte or inserts one header, and the
DKIM-Signature bytes stay equal to a corpus parent. Re-verify the ten most
common messages in each status class, then revert that single edit and
re-verify. A class is minimal when the revert no longer has the same split.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
FUZZ = RUN / "fuzz"
OUT = FUZZ / "minimized"
PARENTS = [
    RUN / "causal/preflight/signed.eml",
    RUN / "causal/cases/from-relaxed-n1-h1-unchanged/mutant.eml",
    RUN / "causal/cases/subject-relaxed-n1-h1-unchanged/mutant.eml",
]


def sig(raw: bytes) -> bytes:
    info = structure.inspect(raw)
    return b"".join(raw[field["start"]:field["end"]] for field in info["fields"] if field["name"] == "dkim-signature")


def locate(digest: str) -> Path | None:
    prefix = digest[:12]
    hits = list(FUZZ.glob(f"*/seed-*/split-{prefix}.eml"))
    return hits[0] if hits else None


def one_edit(raw: bytes, parent: bytes) -> tuple[str, bytes] | None:
    if sig(raw) != sig(parent) or raw == parent:
        return None
    if len(raw) == len(parent):
        changed = [i for i, (a, b) in enumerate(zip(raw, parent)) if a != b]
        if len(changed) == 1:
            return "one-byte", parent
        return None
    if len(raw) < len(parent):
        return None
    shared = 0
    while shared < len(parent) and raw[shared] == parent[shared]:
        shared += 1
    extra = len(raw) - len(parent)
    if raw[shared + extra:] == parent[shared:]:
        return "inserted-line", parent
    return None


def container_path(path: Path) -> str:
    rel = path.relative_to(RUN)
    return "/evidence/w1-20261001a/" + rel.as_posix()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    parents = [(path, path.read_bytes()) for path in PARENTS if path.exists()]
    grouped: dict[str, Counter] = defaultdict(Counter)
    for events in FUZZ.glob("*/seed-*/events.jsonl"):
        for line in events.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            row = json.loads(line)
            if not row.get("split"):
                continue
            key = json.dumps(row["statuses"], sort_keys=True)
            grouped[key][row["sha256"]] += 1

    report = []
    for key, counts in sorted(grouped.items(), key=lambda item: -sum(item[1].values())):
        chosen = counts.most_common(10)
        klass = {"statuses": json.loads(key), "candidates": []}
        for digest, times in chosen:
            path = locate(digest)
            item = {"sha256": digest, "times": times, "stored": bool(path)}
            if path is None:
                klass["candidates"].append(item)
                continue
            raw = path.read_bytes()
            item["file"] = str(path.relative_to(FUZZ))
            item["signature_matches_parent"] = any(sig(raw) == sig(parent) for _, parent in parents)
            match = None
            for _, parent in parents:
                edit = one_edit(raw, parent)
                if edit:
                    match = (edit[0], parent)
                    break
            item["edit"] = match[0] if match else "not-one-edit"
            fresh = verify_file(container_path(path))
            item["reverified"] = {name: value.get("status") for name, value in fresh.items()}
            same = item["reverified"] == klass["statuses"]
            item["split_reproduced"] = same
            if match:
                reverted = OUT / f"revert-{digest[:12]}.eml"
                reverted.write_bytes(match[1])
                again = verify_file(container_path(reverted))
                item["reverted"] = {name: value.get("status") for name, value in again.items()}
                item["minimal"] = item["reverted"] != item["reverified"]
            klass["candidates"].append(item)
            print(json.dumps({"class": klass["statuses"], "sha": digest[:12], "edit": item["edit"], "reproduced": same}), flush=True)
        report.append(klass)
    write_json(OUT / "report.json", report)
    print("classes", len(report))


if __name__ == "__main__":
    main()
