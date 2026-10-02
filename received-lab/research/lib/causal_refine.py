"""Cross-case root causes, plus oversign signatures that omit the null field."""
from __future__ import annotations

import json
from pathlib import Path

from research import corpus, reference, structure
from research.lib.causal import header_names, verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
STAGE = RUN / "causal"


def load_rows():
    return json.loads((STAGE / "matrix.json").read_text(encoding="utf-8"))


def status_of(rows, **want):
    for row in rows:
        if all(row.get(key) == value for key, value in want.items()):
            return row
    return None


def joint(before, after):
    if not before or not after:
        return "missing-pair"
    out = {}
    for name in ("dkimpy", "perl", "go", "rspamd"):
        b, a = before["verifiers"][name], after["verifiers"][name]
        if b == "pass" and a == "fail":
            out[name] = "bottom-up-instance"
        elif b == "fail" and a == "pass":
            out[name] = "top-down-instance"
        elif b == "fail" and a == "fail":
            out[name] = "fails-when-either-instance-is-added"
        elif b == "pass" and a == "pass":
            out[name] = "added-instance-ignored"
        else:
            out[name] = f"{b}/{a}"
    return out


def oversign_omit(run_id="w1-20261001a"):
    key = RUN / "keys" / "priv.pem"
    pub = RUN / "keys" / "pub.pem"
    rows = []
    for field in ("from", "subject", "message-id"):
        for mode in ("relaxed", "simple"):
            names = header_names(field, 2)
            unsigned = corpus.base(f"omit-{field}-{mode}")
            signed, meta = reference.sign(
                unsigned, key, names, mode=mode, domain="lab.test", selector="cal", include_missing=False,
            )
            for operation in ("unchanged", "insert-before", "insert-after"):
                mutant = corpus.mutate(signed, field, operation)
                case = f"omit-{field}-{mode}-{operation}"
                path = STAGE / "oversign-omit" / case
                path.mkdir(parents=True, exist_ok=True)
                (path / "mutant.eml").write_bytes(mutant)
                bottom = reference.diagnose(mutant, pub, include_missing=False)
                verdicts = verify_file(f"/evidence/{run_id}/causal/oversign-omit/{case}/mutant.eml")
                row = {
                    "case": case,
                    "field": field,
                    "header_canon": mode,
                    "operation": operation,
                    "signing": "dkimpy-compatible-omit-missing-h-name",
                    "sha256": sha256_bytes(mutant),
                    "reference": bottom.get("status"),
                    "verifiers": {name: item.get("status") for name, item in verdicts.items()},
                    "sign_meta": meta,
                }
                write_json(path / "case.json", row)
                rows.append(row)
                print(case, row["reference"], row["verifiers"], flush=True)
    write_json(STAGE / "oversign-omit.json", rows)
    return rows


def write_conclusions(rows, omit_rows):
    lines = [
        "# Week 2 root cause",
        "",
        "The signature bytes are fixed before each edit. The reference implements RFC 6376 section 3.5 bottom-up selection.",
        "A single-row match to the top-down oracle is not treated as proof of that algorithm when the opposite insertion fails as well.",
        "",
        "dkimpy 1.1.8 default `h=` is `from:to:date:subject:message-id:from`. Its `select_headers()` does not hash a missing extra name.",
        "Signatures in the main matrix that repeat a name with no remaining instance include that null field. All four verifiers reject those unchanged controls.",
        "The omit-missing series below signs the same repeated `h=` without the null field.",
        "",
        "## Position pairs",
        "",
    ]
    joints = []
    for field in ("from", "subject", "message-id"):
        for mode in ("relaxed", "simple"):
            before = status_of(rows, field=field, header_canon=mode, instances_at_sign=1, h_repeats=1, operation="insert-before")
            after = status_of(rows, field=field, header_canon=mode, instances_at_sign=1, h_repeats=1, operation="insert-after")
            pattern = joint(before, after)
            joints.append({"field": field, "header_canon": mode, "pattern": pattern})
            lines.append(f"- {field} {mode}/relaxed h= once: {pattern}")
    lines.extend(["", "## Omit-missing oversign", ""])
    for row in omit_rows:
        lines.append(f"- {row['case']}: reference={row['reference']} verifiers={row['verifiers']}")
    text = "\n".join(lines) + "\n"
    (STAGE / "ROOT.md").write_text(text, encoding="utf-8")
    record = STAGE / "RECORD.md"
    previous = record.read_text(encoding="utf-8") if record.exists() else ""
    record.write_text(previous + "\n" + text, encoding="utf-8")
    unexplained = []
    for row in rows:
        if "unexplained" not in row["causes"].values():
            continue
        if row["h_repeats"] > row["instances_at_sign"] and row["reference_bottom"] == "pass" and set(row["verifiers"].values()) == {"fail"}:
            continue
        unexplained.append(row["case"])
    omit_control_ok = all(
        row["operation"] == "unchanged" and row["reference"] == "pass" and set(row["verifiers"].values()) == {"pass"}
        for row in omit_rows if row["operation"] == "unchanged"
    ) or any(row["operation"] == "unchanged" and set(row["verifiers"].values()) == {"pass"} for row in omit_rows)
    # The control requirement is every unchanged omit-missing signature.
    omit_control_ok = all(
        row["reference"] == "pass" and all(status == "pass" for status in row["verifiers"].values())
        for row in omit_rows if row["operation"] == "unchanged"
    )
    problems = []
    if unexplained:
        problems.append("still unexplained: " + ",".join(unexplained))
    if not omit_control_ok:
        problems.append("omit-missing oversign control did not pass all verifiers")
    report = {
        "stage": "causal",
        "passed": not problems,
        "problems": problems,
        "joints": joints,
        "oversign_rfc_null_rejected": True,
        "counts_as_finding": False,
        "note": "Instance selection and the extra-From failure are mechanisms already discussed around RFC 6376 section 5.4.2. They are recorded here with fixed signatures.",
    }
    write_json(STAGE / "gate.json", report)
    print(json.dumps({"passed": report["passed"], "problems": problems}, indent=2))


def main():
    rows = load_rows()
    omit_rows = oversign_omit()
    write_conclusions(rows, omit_rows)


if __name__ == "__main__":
    main()
