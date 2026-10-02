"""Weeks 5-8. Expensive relay loops and the 10k rspamd sample run only when week 4 reports a method gain.

The three-repeat check, the defense rules on the generated corpus, and the unsent disclosure draft always run.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from research import structure
from research.lib.causal import verify_file
from research.lib.evidence import write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")


def _repeat_minimal() -> list[dict]:
    target = "/evidence/w1-20261001a/causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml"
    rows = []
    for i in range(3):
        verdicts = verify_file(target)
        rows.append({"repeat": i + 1, "statuses": {name: item.get("status") for name, item in verdicts.items()}})
    return rows


def _defenses(raw: bytes) -> dict:
    info = structure.inspect(raw)
    names = {}
    for field in info["fields"]:
        names.setdefault(field["name"], []).append(field)
    ambiguous = any(len(items) > 1 or any(item["syntax"] != "modern" for item in items) for key, items in names.items() if key in {"from", "subject", "message-id"})
    froms = names.get("from", [])
    displayed = froms[0]["index"] if froms else None
    hashed = froms[-1]["index"] if froms else None
    return {
        "reject_ambiguous_before_auth": ambiguous,
        "invalidate_if_display_from_is_not_hashed_from": displayed is not None and displayed != hashed,
    }


def _corpus_10k(stage: Path) -> dict:
    """Controlled families. List-rewrite copies are marked expected-signature-fail and are not counted as misses."""
    families = ("direct", "forward", "list-rewrite", "multilingual", "folded")
    counts = {name: 0 for name in families}
    dev_hits = {name: {"ambiguous": 0, "bound": 0} for name in families}
    hold_hits = {name: {"ambiguous": 0, "bound": 0} for name in families}
    for i in range(10000):
        family = families[i % 5]
        holdout = (i // 5) % 5 == 4
        if family == "direct":
            raw = b"From: Author <author@lab.test>\r\nSubject: n\r\n\r\nbody\r\n"
        elif family == "forward":
            raw = b"From: Author <author@lab.test>\r\nReceived: from a.example by b.example; Thu, 1 Oct 2026 00:00:00 +0000\r\nSubject: n\r\n\r\nbody\r\n"
        elif family == "list-rewrite":
            raw = b"From: List <list@lab.test>\r\nFrom: Author <author@lab.test>\r\nSubject: [list] n\r\n\r\nbody\r\n"
        elif family == "multilingual":
            raw = "From: 作者 <author@lab.test>\r\nSubject: 测试\r\n\r\n正文\r\n".encode()
        else:
            raw = b"From: Author <author@lab.test>\r\nSubject: hello\r\n world\r\n\r\nbody\r\n"
        decision = _defenses(raw)
        bucket = hold_hits if holdout else dev_hits
        bucket[family]["ambiguous"] += int(decision["reject_ambiguous_before_auth"])
        bucket[family]["bound"] += int(decision["invalidate_if_display_from_is_not_hashed_from"])
        counts[family] += 1
    summary = {
        "messages": 10000,
        "family_counts": counts,
        "development": dev_hits,
        "holdout": hold_hits,
        "list_rewrite_expected_signature_failure": True,
        "product_rspamd_sample": "not run when week 4 stops expansion; the in-process rules are the measured defenses",
    }
    write_json(stage / "defense-10k.json", summary)
    return summary


def _paper(stage: Path, repeats: list[dict], defense: dict, stop: bool) -> None:
    text = f"""# Paper skeleton (not submitted)

## Question

After a message is received, repaired, authenticated, and parsed, is the identity covered by the signature the identity a later component uses?

## What this run supports

- With one `h=` listing, perl Mail::DKIM and go-msgauth 0.6.8 follow bottom-up selection for From, Subject, and Message-ID. Adding a field above the signed instance keeps their result at pass. Adding it below changes the result to fail.
- dkimpy 1.1.8 and rspamd 3.4 fail when a second From is added in either position. For Subject and Message-ID, dkimpy still follows bottom-up selection, while rspamd fails for an added instance in either position.
- Repeating the field name in `h=` and omitting the null slot at signing time makes all four verifiers fail when an instance is added above or below. dkimpy 1.1.8 `select_headers()` does not hash a missing name, and a signature that includes the RFC null field is rejected by all four.
- The same From-above mutant is still accepted by perl and go-msgauth after three Postfix hops and is delivered. dkimpy still fails. This run did not capture Roundcube or SnappyMail.
- Three immediate repeats of that mutant: {json.dumps(repeats, ensure_ascii=False)}

## What it does not support

These selection and oversign behaviors are the RFC 6376 section 3.5 and section 5.4.2 mechanisms, in the same family as the composition failures in Chen, Paxson, and Jiang (USENIX Security 2020). They are not reported here as a new vulnerability. Lab DNS used DMARC `p=none`. No Gmail or Exchange measurement was done.

Week 4 stop_expansion={stop}. The 10k rows exercise two local rules (reject ambiguous identity fields; invalidate a display From that is not the bottom-up instance). List rewrite is an expected signature failure, not a miss.

## Disclosure draft (not sent)

No vendor has been contacted. A future notice, if the evidence later supports one, would describe the verifier split on a fixed signature when a second From is inserted above the signed instance, name the versions above, and include the mutant SHA-256 from `causal/cases/from-relaxed-n1-h1-insert-before/case.json`. This file is only that draft.
"""
    (stage / "PAPER_SKELETON.md").write_text(text, encoding="utf-8")
    (stage / "DISCLOSURE_DRAFT.md").write_text(text, encoding="utf-8")
    write_json(stage / "defense.json", defense)


def _maintained_version() -> dict:
    import subprocess
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "postconf", "received-lab-postfix1n:latest", "-h", "mail_version"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60,
    )
    return {"image": "received-lab-postfix1n:latest", "mail_version": proc.stdout.decode().strip(), "stderr": proc.stderr.decode()[-300:]}


def _bounded_opensmtpd() -> dict:
    """Two relays pointed at each other. The parent stops them at 60s. One message."""
    import subprocess
    import textwrap
    conf_a = textwrap.dedent("""
    listen on 0.0.0.0 port 25 hostname osmtpd-a.lab.test
    action "peer" relay host smtp://msl-osmtpd-b:25
    match from any for any action "peer"
    """)
    conf_b = conf_a.replace("osmtpd-a", "osmtpd-b").replace("msl-osmtpd-b", "msl-osmtpd-a")
    stage = RUN / "week5"
    stage.mkdir(parents=True, exist_ok=True)
    (stage / "a.conf").write_text(conf_a, encoding="ascii")
    (stage / "b.conf").write_text(conf_b, encoding="ascii")
    net = "mailseclab-research-net"
    base = ["docker", "run", "-d", "--network", net, "--cpus", "0.4", "--memory", "256m"]
    subprocess.run(["docker", "rm", "-f", "msl-osmtpd-a", "msl-osmtpd-b"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        subprocess.run(base + ["--name", "msl-osmtpd-a", "-v", f"{stage / 'a.conf'}:/etc/smtpd.conf:ro", "received-lab-opensmtpd:latest"], check=True)
        subprocess.run(base + ["--name", "msl-osmtpd-b", "-v", f"{stage / 'b.conf'}:/etc/smtpd.conf:ro", "received-lab-opensmtpd:latest"], check=True)
        time.sleep(2)
        subprocess.run(["docker", "start", "msl-client"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # One ordinary Received and stop. The cap is the parent's 60s, not an open-ended loop.
        started = time.time()
        subprocess.run(["docker", "exec", "msl-client", "python3", "-c",
                        "import socket;s=socket.create_connection(('msl-osmtpd-a',25),5);s.sendall(b'EHLO client.lab.test\\r\\nMAIL FROM:<a@lab.test>\\r\\nRCPT TO:<b@lab.test>\\r\\nDATA\\r\\nSubject: loop-cap\\r\\n\\r\\nloop\\r\\n.\\r\\nQUIT\\r\\n');s.close()"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        while time.time() - started < 60:
            time.sleep(2)
        logs = subprocess.run(["docker", "logs", "msl-osmtpd-a"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20).stdout
        (stage / "osmtpd-a.log").write_bytes(logs)
        return {"stopped_after_seconds": round(time.time() - started, 1), "log_bytes": len(logs), "cap": "60s or container stop, one injected message"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        subprocess.run(["docker", "rm", "-f", "msl-osmtpd-a", "msl-osmtpd-b"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_rest(run_id: str = "w1-20261001a") -> dict:
    stage = RUN / "report"
    stage.mkdir(parents=True, exist_ok=True)
    fuzz_gate = json.loads((RUN / "fuzz" / "gate.json").read_text(encoding="utf-8"))
    stop = bool(fuzz_gate.get("stop_expansion"))
    repeats = _repeat_minimal()
    maintained = _maintained_version()
    loop = None if stop else _bounded_opensmtpd()
    defense = _corpus_10k(stage)
    write_json(stage / "maintained.json", {"postfix_3_11_image": maintained, "opensmtpd_bounded": loop})
    _paper(stage, repeats, defense, stop)
    note = "Week 5 relay loops and the rspamd 10k sample were not started." if stop else "Week 4 reported a method gain; expensive follow-ups still require the maintained-version freeze before they are cited."
    report = {
        "stage": "report",
        "passed": all(set(row["statuses"].values()) == {"fail", "pass"} or "fail" in row["statuses"].values() for row in repeats),
        "problems": [],
        "repeats": repeats,
        "stop_expansion": stop,
        "note": note,
        "disclosure_sent": False,
        "counts_as_finding": False,
    }
    write_json(stage / "gate.json", report)
    (stage / "RECORD.md").write_text("# Weeks 5-8\n\n" + note + "\n\nRepeats:\n\n" + json.dumps(repeats, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stop_expansion": stop, "repeats": repeats}, indent=2), flush=True)
    return report
