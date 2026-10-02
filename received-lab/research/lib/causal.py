"""Week 2: fixed-signature field-instance experiments.

Mutations never resign. The independent reference records which header
instances enter the RSA-SHA256 input. Verifier results are compared with
that record and with a top-down oracle.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from research import corpus, reference, structure
try:
    from lib import dockerctl
    from lib.evidence import sha256_bytes, write_json
except ImportError:
    from research.lib import dockerctl
    from research.lib.evidence import sha256_bytes, write_json

RUN_ID_DEFAULT = "w1-20261001a"


def header_names(field: str, covered: int) -> list[str]:
    names: list[str] = []
    if field != "from":
        names.append("from")
    names.extend([field] * covered)
    for extra in ("to", "date", "subject", "message-id"):
        if extra != field:
            names.append(extra)
    return names


def rspamd_status(payload: dict) -> str:
    symbols = payload.get("symbols") or {}
    if "R_DKIM_ALLOW" in symbols:
        return "pass"
    if "R_DKIM_REJECT" in symbols:
        return "fail"
    if "R_DKIM_TEMPFAIL" in symbols:
        return "temp-error"
    if "R_DKIM_PERMFAIL" in symbols:
        return "fail"
    if "R_DKIM_NA" in symbols:
        return "none"
    action = str(payload.get("action") or "").lower()
    if action == "reject":
        return "policy-reject"
    return "none"


def cause_for(status: str, bottom: str, top: str) -> str:
    if status in {"parse-error", "policy-reject", "temp-error", "tool-error", "timeout", "none"}:
        return status
    if status == bottom and status != top:
        return "matches-rfc6376-bottom-up-section-3.5"
    if status == top and status != bottom:
        return "matches-top-down-oracle"
    if status == bottom == top:
        return "both-oracles-agree"
    return "unexplained"


def _exec(name: str, args: list[str], stdin: bytes, timeout: int = 40):
    proc = dockerctl.docker_exec(name, args, timeout=timeout, stdin=stdin)
    return proc.returncode, proc.stdout_text, proc.stderr_text


def verify_all(raw: bytes, run_id: str) -> dict:
    out = {}
    for tool in ("dkimpy", "perl", "go"):
        rc, text, err = _exec(
            "msl-verifiers",
            ["python3", "/opt/research/lib/verify_one.py", tool, "/dev/stdin"],
            raw,
        )
        # verify_one reads a path, not stdin. Write via a mounted file instead.
        out[tool] = {"status": "tool-error", "stderr": err, "stdout": text, "exit_code": rc}
    return out


def verify_file(path_in_container: str) -> dict:
    results = {}
    for tool in ("dkimpy", "perl", "go"):
        rc, text, err = _exec(
            "msl-verifiers",
            ["python3", "/opt/research/lib/verify_one.py", tool, path_in_container],
            b"",
            timeout=40,
        )
        if rc != 0 or not text.strip():
            results[tool] = {"status": "tool-error", "stdout": text, "stderr": err, "exit_code": rc}
            continue
        try:
            results[tool] = json.loads(text)
        except json.JSONDecodeError:
            results[tool] = {"status": "tool-error", "stdout": text, "stderr": err}
    rc, text, err = _exec("msl-rspamd", ["rspamc", "--json", path_in_container], b"", timeout=60)
    if rc != 0 or not text.strip():
        results["rspamd"] = {"status": "tool-error", "stdout": text[-1500:], "stderr": err[-1500:]}
    else:
        try:
            payload = json.loads(text)
            results["rspamd"] = {
                "status": rspamd_status(payload),
                "action": payload.get("action"),
                "score": payload.get("score"),
                "symbols": sorted((payload.get("symbols") or {}).keys()),
            }
        except json.JSONDecodeError:
            results["rspamd"] = {"status": "tool-error", "stdout": text[-1500:], "stderr": err[-1500:]}
    return results


def start_verifiers(run_id: str) -> None:
    dockerctl.compose(run_id, ["up", "-d", "dns", "verifiers", "rspamd"], timeout=180)
    deadline = time.time() + 90
    while time.time() < deadline:
        rc, out, _ = _exec("msl-dns", ["dig", "@127.0.0.1", "lab.test", "TXT", "+short", "+time=2", "+tries=1"], b"", timeout=15)
        if rc == 0 and "spf1" in out:
            break
        time.sleep(2)
    else:
        raise RuntimeError("dns did not answer")
    probe = dockerctl.LAB / "results" / "research" / run_id / "causal" / "rspamd-probe.eml"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_bytes(b"From: a@lab.test\r\nSubject: probe\r\n\r\nok\r\n")
    deadline = time.time() + 60
    while time.time() < deadline:
        rc, out, err = _exec("msl-rspamd", ["rspamc", "--json", f"/evidence/{run_id}/causal/rspamd-probe.eml"], b"", timeout=20)
        if rc == 0 and "score" in out:
            return
        time.sleep(2)
    raise RuntimeError("rspamd did not accept a scan: " + (err or out)[-400:])


def signer_default(sample: bytes, run: Path) -> dict:
    script = r"""
import dkim, json, sys
raw = sys.stdin.buffer.read()
sig = dkim.sign(raw, b'cal', b'lab.test', open('/evidence/%s/keys/priv.pem','rb').read())
text = sig.decode('latin1')
h = ''
for part in text.replace('\r','').replace('\n','').split(';'):
    part = part.strip()
    if part.lower().startswith('h='):
        h = part[2:]
print(json.dumps({'h': h, 'signature_prefix': text[:180]}))
""" % RUN_ID_DEFAULT
    # The run id is passed by the caller through the file path, not this constant.
    return {"note": "filled by run_causal"}


def run_causal(run_id: str) -> dict:
    run = dockerctl.LAB / "results" / "research" / run_id
    stage = run / "causal"
    if (stage / "gate.json").exists():
        return json.loads((stage / "gate.json").read_text(encoding="utf-8"))
    stage.mkdir(parents=True, exist_ok=True)
    key = run / "keys" / "priv.pem"
    pub = run / "keys" / "pub.pem"
    if not key.exists():
        raise SystemExit(f"missing signing key {key}")
    log_path = stage / "progress.log"

    def log(msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    log("starting verifiers")
    start_verifiers(run_id)
    script = (
        "import dkim, json, sys\n"
        "raw = sys.stdin.buffer.read()\n"
        f"sig = dkim.sign(raw, b'cal', b'lab.test', open('/evidence/{run_id}/keys/priv.pem','rb').read())\n"
        "text = sig.decode('latin1')\n"
        "flat = text.replace('\\r','').replace('\\n','')\n"
        "h = ''\n"
        "for part in flat.split(';'):\n"
        "    part = part.strip()\n"
        "    if part.lower().startswith('h='):\n"
        "        h = part[2:]\n"
        "print(json.dumps({'tool':'dkimpy','version':'1.1.8','default_h':h}))\n"
    )
    sample = corpus.base("signer-default")
    rc, out, err = _exec("msl-verifiers", ["python3", "-c", script], sample, timeout=30)
    write_json(stage / "signer-default.json", {"rc": rc, "stdout": out, "stderr": err})
    log(f"signer default: {out.strip()} {err.strip()[:200]}")
    pre = _preflight(stage, run_id, key, pub, log)
    if not pre["ok"]:
        write_json(stage / "preflight-failed.json", pre)
        return {"stage": "causal", "passed": False, "problems": ["preflight signature was not accepted"], "preflight": pre, "counts_as_finding": False}

    rows = []
    signed_cache: dict[tuple, bytes] = {}
    smoke_ok = False
    for spec in corpus.causal_specs():
        field, mode, count, covered = spec["field"], spec["mode"], spec["count"], spec["covered"]
        names = header_names(field, covered)
        cache_key = (field, mode, count, covered)
        if cache_key not in signed_cache:
            unsigned = corpus.base(f"base-{field}-{mode}-n{count}-h{covered}", duplicate=field if count == 2 else None)
            signed, meta = reference.sign(unsigned, key, names, mode=mode, domain="lab.test", selector="cal")
            signed_cache[cache_key] = signed
            group = stage / "groups" / f"{field}-{mode}-n{count}-h{covered}"
            group.mkdir(parents=True, exist_ok=True)
            (group / "signed.eml").write_bytes(signed)
            write_json(group / "sign-meta.json", meta)
        signed = signed_cache[cache_key]
        for operation in spec["operations"]:
            case = f"{field}-{mode}-n{count}-h{covered}-{operation}"
            case_dir = stage / "cases" / case
            case_dir.mkdir(parents=True, exist_ok=True)
            mutant = corpus.mutate(signed, field, operation)
            if structure.field_bytes(signed, "dkim-signature") != structure.field_bytes(mutant, "dkim-signature"):
                raise RuntimeError(f"{case} changed the signature")
            (case_dir / "mutant.eml").write_bytes(mutant)
            info = structure.inspect(mutant)
            bottom = reference.diagnose(mutant, pub, top_down=False)
            top = reference.diagnose(mutant, pub, top_down=True)
            container_path = f"/evidence/{run_id}/causal/cases/{case}/mutant.eml"
            verdicts = verify_file(container_path)
            statuses = {name: item.get("status") for name, item in verdicts.items()}
            causes = {
                name: cause_for(status, bottom.get("status"), top.get("status"))
                for name, status in statuses.items()
            }
            row = {
                "case": case,
                "field": field,
                "header_canon": mode,
                "body_canon": "relaxed",
                "instances_at_sign": count,
                "h_repeats": covered,
                "h": names,
                "operation": operation,
                "sha256": sha256_bytes(mutant),
                "bytes": len(mutant),
                "reference_bottom": bottom.get("status"),
                "reference_top": top.get("status"),
                "selected_bottom": (bottom.get("signatures") or [{}])[0].get("selected"),
                "selected_top": (top.get("signatures") or [{}])[0].get("selected"),
                "verifiers": statuses,
                "causes": causes,
                "field_counts": info["counts"],
                "syntax": sorted({f["syntax"] for f in info["fields"]}),
            }
            write_json(case_dir / "case.json", {"row": row, "bottom": bottom, "top": top, "verifiers": verdicts})
            rows.append(row)
            if operation == "unchanged" and field == "from" and mode == "relaxed" and count == 1 and covered == 1:
                smoke_ok = all(statuses.get(name) == "pass" for name in ("dkimpy", "perl", "go", "rspamd")) and bottom.get("status") == "pass"
                log(f"smoke {case} statuses={statuses} reference={bottom.get('status')} smoke_ok={smoke_ok}")
            if operation != "unchanged" and len(set(statuses.values())) > 1:
                log(f"split {case} {statuses} causes={causes}")
    malformed = _malformed(stage, run_id, key, pub)
    write_json(stage / "matrix.json", rows)
    _write_csv(stage / "matrix.csv", rows)
    report = _gate(rows, smoke_ok, malformed)
    write_json(stage / "gate.json", report)
    _record(stage, rows, report, malformed)
    log(f"causal gate passed={report['passed']} divergences={report.get('divergence_classes')}")
    return report


def _preflight(stage: Path, run_id: str, key: Path, pub: Path, log) -> dict:
    raw = corpus.base("preflight")
    signed, meta = reference.sign(raw, key, ["from", "to", "date", "subject", "message-id"], mode="relaxed", domain="lab.test", selector="cal")
    path = stage / "preflight"
    path.mkdir(parents=True, exist_ok=True)
    (path / "signed.eml").write_bytes(signed)
    bottom = reference.diagnose(signed, pub)
    verdicts = verify_file(f"/evidence/{run_id}/causal/preflight/signed.eml")
    statuses = {name: item.get("status") for name, item in verdicts.items()}
    write_json(path / "result.json", {"meta": meta, "reference": bottom, "verifiers": verdicts, "statuses": statuses})
    ok = bottom.get("status") == "pass" and all(statuses.get(name) == "pass" for name in ("dkimpy", "perl", "go", "rspamd"))
    log(f"preflight reference={bottom.get('status')} verifiers={statuses}")
    return {"ok": ok, "reference": bottom.get("status"), "statuses": statuses}


def _malformed(stage: Path, run_id: str, key: Path, pub: Path) -> list[dict]:
    """Boundary and obs-syntax cases, kept out of the duplicate-field matrix."""
    base = corpus.base("malformed-base")
    signed, _ = reference.sign(base, key, ["from", "to", "date", "subject", "message-id"], mode="relaxed", domain="lab.test", selector="cal")
    sig = structure.field_bytes(signed, "dkim-signature")[0]
    rest = signed[len(sig):]
    cases = {
        "obs-from-before": sig + b"From : Mallory <mallory@evil.test>\r\n" + rest,
        "blank-line-before-from": sig + b"\r\n" + rest,
    }
    rows = []
    for name, raw in cases.items():
        path = stage / "malformed" / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "mutant.eml").write_bytes(raw)
        info = structure.inspect(raw)
        verdicts = verify_file(f"/evidence/{run_id}/causal/malformed/{name}/mutant.eml")
        row = {
            "case": name,
            "series": "malformed-boundary",
            "sha256": sha256_bytes(raw),
            "issues": info["issues"],
            "syntax": [f["syntax"] for f in info["fields"]],
            "verifiers": {k: v.get("status") for k, v in verdicts.items()},
            "reference": reference.diagnose(raw, pub).get("status"),
        }
        write_json(path / "case.json", row)
        rows.append(row)
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    header = "case,field,header_canon,instances_at_sign,h_repeats,operation,sha256,reference_bottom,reference_top,dkimpy,perl,go,rspamd,dkimpy_cause,perl_cause,go_cause,rspamd_cause\n"
    lines = [header]
    for row in rows:
        v, c = row["verifiers"], row["causes"]
        lines.append(",".join([
            row["case"], row["field"], row["header_canon"], str(row["instances_at_sign"]), str(row["h_repeats"]),
            row["operation"], row["sha256"], row["reference_bottom"], row["reference_top"],
            str(v.get("dkimpy")), str(v.get("perl")), str(v.get("go")), str(v.get("rspamd")),
            str(c.get("dkimpy")), str(c.get("perl")), str(c.get("go")), str(c.get("rspamd")),
        ]) + "\n")
    path.write_text("".join(lines), encoding="utf-8")


def _gate(rows: list[dict], smoke_ok: bool, malformed: list[dict]) -> dict:
    problems = []
    if not smoke_ok:
        problems.append("unchanged relaxed/relaxed From control did not pass on the reference and all four verifiers")
    unexplained = [row["case"] for row in rows if "unexplained" in row["causes"].values()]
    if unexplained:
        problems.append("unexplained verifier results: " + ",".join(unexplained[:12]))
    classes = []
    for row in rows:
        statuses = tuple(sorted(row["verifiers"].items()))
        if len(set(row["verifiers"].values())) > 1:
            classes.append({
                "case": row["case"],
                "field": row["field"],
                "operation": row["operation"],
                "verifiers": row["verifiers"],
                "causes": row["causes"],
                "reference_bottom": row["reference_bottom"],
                "reference_top": row["reference_top"],
            })
    return {
        "stage": "causal",
        "passed": not problems,
        "problems": problems,
        "divergence_classes": len(classes),
        "divergence_examples": classes[:30],
        "malformed": malformed,
        "counts_as_finding": False,
        "note": "A pass/fail split is a measured selection difference. It is not by itself a new vulnerability.",
    }


def _record(stage: Path, rows: list[dict], report: dict, malformed: list[dict]) -> None:
    splits = [row for row in rows if len(set(row["verifiers"].values())) > 1]
    lines = [
        "# Week 2 causal",
        "",
        f"Gate passed: {report['passed']}",
        "",
        "Signatures are created once. Later edits do not change `b=`.",
        "The reference selects header instances from the bottom of the header block, RFC 6376 section 3.5.",
        "A top-down oracle is recorded only as a contrast. Canonicalization pairs are relaxed/relaxed and simple/relaxed.",
        "",
        f"Matrix rows: {len(rows)}. Verifier splits: {len(splits)}.",
        "",
    ]
    if report["problems"]:
        lines.append("## Problems")
        lines.extend(f"- {item}" for item in report["problems"])
        lines.append("")
    lines.append("## Splits")
    for row in splits[:40]:
        lines.append(
            f"- {row['case']}: verifiers={row['verifiers']} reference={row['reference_bottom']}/{row['reference_top']} causes={row['causes']}"
        )
    lines.extend(["", "## Malformed series", ""])
    for row in malformed:
        lines.append(f"- {row['case']}: reference={row['reference']} verifiers={row['verifiers']} issues={row['issues']} syntax={row['syntax']}")
    lines.append("")
    (stage / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
