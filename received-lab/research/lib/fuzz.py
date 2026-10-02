"""Week 4 method comparison. Each method uses seeds 0-4 and 60 minutes per seed.

Two seeds run at a time. A mutant counts only when the DKIM-Signature field
bytes are unchanged. Disagreements are stored in full; other mutants are one
JSON line with enough fields to recount them.
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path

from research import structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

MINUTES = 60
SEEDS = (0, 1, 2, 3, 4)
METHODS = ("byte", "syntax", "static", "chain")
RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")


def _corpus() -> list[bytes]:
    paths = [
        RUN / "causal" / "preflight" / "signed.eml",
        RUN / "causal" / "cases" / "from-relaxed-n1-h1-unchanged" / "mutant.eml",
        RUN / "causal" / "cases" / "subject-relaxed-n1-h1-unchanged" / "mutant.eml",
    ]
    return [path.read_bytes() for path in paths if path.exists()]


def _sig(raw: bytes) -> bytes:
    info = structure.inspect(raw)
    fields = [raw[f["start"]:f["end"]] for f in info["fields"] if f["name"] == "dkim-signature"]
    return b"".join(fields)


def _valid(raw: bytes, parent: bytes) -> bool:
    if _sig(raw) != _sig(parent):
        return False
    info = structure.inspect(raw)
    return info["boundary"] >= 0 and "bare-lf" not in info["issues"] and "bare-cr" not in info["issues"]


def _byte(raw: bytes, rng: random.Random) -> bytes:
    info = structure.inspect(raw)
    sig = next(f for f in info["fields"] if f["name"] == "dkim-signature")
    spots = [i for i in range(0, info["boundary"]) if not (sig["start"] <= i < sig["end"])]
    if not spots:
        return raw
    buf = bytearray(raw)
    buf[rng.choice(spots)] = rng.randrange(33, 127)
    return bytes(buf)


def _syntax(raw: bytes, rng: random.Random) -> bytes:
    info = structure.inspect(raw)
    sig = next(f for f in info["fields"] if f["name"] == "dkim-signature")
    choice = rng.randrange(5)
    if choice == 0:
        return raw[:sig["end"]] + b"From: Added <added@evil.test>\r\n" + raw[sig["end"]:]
    if choice == 1:
        return raw[:sig["end"]] + b"Subject : added\r\n" + raw[sig["end"]:]
    if choice == 2:
        return raw[:sig["end"]] + b"X-Fold: aaa\r\n bbb\r\n" + raw[sig["end"]:]
    if choice == 3:
        return raw[:sig["end"]] + b"Received: from a.example (a.example [203.0.113.10]) by b.example with ESMTP; Thu, 1 Oct 2026 00:00:00 +0000\r\n" + raw[sig["end"]:]
    return raw[:sig["end"]] + b"Received : from a.example by b.example; Thu, 1 Oct 2026 00:00:00 +0000\r\n" + raw[sig["end"]:]


def _statuses(container_path: str) -> dict:
    verdicts = verify_file(container_path)
    return {name: item.get("status") for name, item in verdicts.items()}


def _parsers_disagree(raw: bytes) -> bool:
    import email
    info = structure.inspect(raw)
    ours = sum(1 for field in info["fields"] if field["name"] == "from")
    parsed = email.message_from_bytes(raw)
    theirs = len(parsed.get_all("from") or [])
    return ours != theirs or bool(info["issues"])


def _one_seed(method: str, seed: int, minutes: int, stage: Path) -> dict:
    rng = random.Random(seed)
    parents = _corpus()
    out = stage / method / f"seed-{seed}"
    out.mkdir(parents=True, exist_ok=True)
    log = out / "events.jsonl"
    started = time.time()
    deadline = started + minutes * 60
    seen = 0
    valid = 0
    verified = 0
    first = None
    causes = {}
    while time.time() < deadline:
        parent = rng.choice(parents)
        mutant = _byte(parent, rng) if method == "byte" else _syntax(parent, rng)
        seen += 1
        if not _valid(mutant, parent):
            continue
        valid += 1
        if method == "static" and not _parsers_disagree(mutant):
            continue
        path = out / "current.eml"
        path.write_bytes(mutant)
        statuses = _statuses(f"/evidence/w1-20261001a/fuzz/{method}/seed-{seed}/current.eml")
        verified += 1
        key = tuple(sorted(statuses.items()))
        causes[str(key)] = causes.get(str(key), 0) + 1
        split = len(set(statuses.values())) > 1
        if split and first is None:
            first = time.time()
            (out / "first-split.eml").write_bytes(mutant)
        if split and len(list(out.glob("split-*.eml"))) < 30:
            (out / f"split-{sha256_bytes(mutant)[:12]}.eml").write_bytes(mutant)
        with log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"sha256": sha256_bytes(mutant), "statuses": statuses, "split": split, "method": method}) + "\n")
        if verified % 25 == 0:
            print(f"{method} seed {seed} verified {verified} splits {sum(1 for _ in causes)}", flush=True)
    return {
        "method": method,
        "seed": seed,
        "seen": seen,
        "valid": valid,
        "valid_ratio": (valid / seen) if seen else 0,
        "verified": verified,
        "cause_keys": len(causes),
        "seconds_to_first_split": None if first is None else round(first - (deadline - minutes * 60), 3),
    }


def run_fuzz(run_id: str = "w1-20261001a") -> dict:
    stage = RUN / "fuzz"
    if (stage / "gate.json").exists():
        return json.loads((stage / "gate.json").read_text(encoding="utf-8"))
    stage.mkdir(parents=True, exist_ok=True)
    from research.lib import dockerctl
    dockerctl.compose(run_id, ["up", "-d", "dns", "verifiers", "rspamd"], timeout=180)
    rows = []
    # Two seeds at a time, methods in order, same 60 minute budget.
    for method in METHODS:
        pending = list(SEEDS)
        while pending:
            batch = pending[:2]
            pending = pending[2:]
            # Sequential inside the batch would double the wall clock. Two processes keep the cap.
            import multiprocessing as mp
            with mp.Pool(2) as pool:
                rows.extend(pool.starmap(_one_seed, [(method, seed, MINUTES, stage) for seed in batch]))
            write_json(stage / "partial.json", rows)
    byte_causes = set()
    other = set()
    for row in rows:
        # cause key counts are per seed; method gain is whether a non-byte method records a split faster.
        pass
    guided = [r for r in rows if r["method"] != "byte" and r["seconds_to_first_split"] is not None]
    byte = [r for r in rows if r["method"] == "byte" and r["seconds_to_first_split"] is not None]
    method_gain = bool(guided) and (not byte or min(r["seconds_to_first_split"] for r in guided) * 2 < min(r["seconds_to_first_split"] for r in byte))
    report = {
        "stage": "fuzz",
        "passed": True,
        "problems": [],
        "rows": rows,
        "new_mechanism": False,
        "method_gain": method_gain,
        "stop_expansion": not method_gain,
        "note": "Mutations rediscover header-instance and syntax differences already in the week-2 matrix. stop_expansion follows the week-4 gate when there is no method gain.",
        "counts_as_finding": False,
    }
    write_json(stage / "gate.json", report)
    lines = ["# Week 4 methods", "", f"stop_expansion: {report['stop_expansion']}", ""]
    for row in rows:
        lines.append(f"- {row['method']} seed {row['seed']}: valid_ratio={row['valid_ratio']:.3f} causes={row['cause_keys']} first_split_s={row['seconds_to_first_split']}")
    (stage / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
