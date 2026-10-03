#!/usr/bin/env python3
"""Research stack entrypoint.

    python3 research/run.py --stage bootstrap --run-id <id>

Stages: bootstrap, causal, e2e, fuzz, defense, report.
Later stages run only after the previous stage's gate exists for the same run-id.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.bootstrap import EVIDENCE, run_bootstrap
from lib.causal import run_causal
from lib.chainrun import run_chain
from lib.diffrun import run_diff
from lib.e2e import run_e2e

STAGES = ("bootstrap", "causal", "e2e", "fuzz", "defense", "report", "diff", "chain")
NEEDS = {
    "causal": ("bootstrap",),
    "e2e": ("bootstrap", "causal"),
    "fuzz": ("bootstrap", "causal", "e2e"),
    "defense": ("bootstrap", "causal", "e2e", "fuzz"),
    "report": ("bootstrap", "causal", "e2e", "fuzz", "defense"),
    "diff": (),
    "chain": (),
}


def prerequisites(stage: str, run_id: str) -> list[str]:
    missing = []
    for earlier in NEEDS.get(stage, ()):
        gate = EVIDENCE / run_id / earlier / "gate.json"
        # bootstrap writes gate.json at the run root; later stages use a subdirectory.
        if earlier == "bootstrap":
            gate = EVIDENCE / run_id / "gate.json"
        if not gate.exists():
            missing.append(str(gate))
    return missing


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if args.stage != "bootstrap":
        missing = prerequisites(args.stage, args.run_id)
        if missing:
            print("missing prerequisite evidence:")
            for item in missing:
                print(" ", item)
            return 2
        runners = {"causal": run_causal, "e2e": run_e2e, "diff": run_diff, "chain": run_chain}
        if args.stage not in runners:
            print(f"stage {args.stage} runner is not dispatched yet")
            return 2
        report = runners[args.stage](args.run_id)
        print(f"{args.stage} gate passed={report['passed']}")
        if report.get("problems"):
            for item in report["problems"]:
                print(" -", item)
        return 0 if report["passed"] else 1
    report = run_bootstrap(args.run_id)
    print(f"bootstrap gate passed={report['passed']}")
    if report["problems"]:
        for item in report["problems"]:
            print(" -", item)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
