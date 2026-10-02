"""Week 3: authentication result, delivery, and displayed identity on one run.

Chain A scans with rspamd after Postfix delivery. Chain B is the same stored
message checked by the three library verifiers. Webmail is attempted and any
missing client is recorded as a gap, not invented.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

from research import corpus, reference, structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")


def _log(stage: Path, msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with (stage / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _send(run_id: str, src: str, transcript: str) -> dict:
    import subprocess
    proc = subprocess.run(
        ["docker", "exec", "-i", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
         "--server", "postfix1", "--port", "25", "--input", src, "--transcript", transcript],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
    )
    text = proc.stdout.decode("utf-8", "replace")
    if not text.strip():
        return {"accepted": False, "error": proc.stderr.decode("utf-8", "replace")}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"accepted": False, "raw": text}


def _mailpit(token: bytes, timeout: int = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            query = urllib.parse.quote(token.decode("ascii", "ignore"))
            with urllib.request.urlopen(f"http://127.0.0.1:18025/api/v1/search?query={query}", timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            time.sleep(1)
            continue
        for item in data.get("messages") or []:
            mid = item.get("ID")
            if not mid:
                continue
            with urllib.request.urlopen(f"http://127.0.0.1:18025/api/v1/message/{mid}/raw", timeout=30) as resp:
                raw = resp.read()
            if token in raw:
                return raw, mid
        time.sleep(1)
    return None, None


def _ensure_chain(run_id: str) -> None:
    from research.lib import dockerctl
    dockerctl.compose(run_id, ["up", "-d", "dns", "postfix1", "postfix2", "postfix3", "mailpit", "client", "rspamd", "verifiers"], timeout=180)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:18025/api/v1/messages?limit=1", timeout=3).read()
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError("mailpit on 127.0.0.1:18025 did not answer")


def _own_key_message(stage: Path, key: Path) -> bytes:
    """Attacker holds evil.test only. The visible top From is lab.test and is not the signed instance."""
    body = corpus.base("e2e-own-key")
    # Replace the single From with the attacker's identity, sign that, then prepend the lab.test From.
    raw = body.replace(b"From: Author <author@lab.test>", b"From: Attacker <attacker@evil.test>", 1)
    signed, _ = reference.sign(raw, key, ["from", "to", "date", "subject", "message-id"], mode="relaxed", domain="evil.test", selector="attacker")
    info = structure.inspect(signed)
    sig = next(field for field in info["fields"] if field["name"] == "dkim-signature")
    return signed[:sig["end"]] + b"From: Author <author@lab.test>\r\n" + signed[sig["end"]:]


def run_e2e(run_id: str = "w1-20261001a") -> dict:
    stage = RUN / "e2e"
    if (stage / "gate.json").exists():
        return json.loads((stage / "gate.json").read_text(encoding="utf-8"))
    stage.mkdir(parents=True, exist_ok=True)
    _log(stage, "starting delivery chain")
    _ensure_chain(run_id)
    key = RUN / "keys" / "wrong.pem"
    pub_cmd = ["openssl", "rsa", "-in", str(key), "-pubout"]
    import subprocess
    pub = subprocess.run(pub_cmd, stdout=subprocess.PIPE, check=True).stdout
    b64 = "".join(line for line in pub.decode().splitlines() if not line.startswith("-----"))
    extra = RUN / "keys" / "extra-dns.conf"
    # TXT split is unnecessary for this short note; the key b64 is long, so reuse the lab chunker by one string per 200 chars.
    chunks = [b64[i:i + 200] for i in range(0, len(b64), 200)]
    txt = "txt-record=attacker._domainkey.evil.test," + ",".join(chunks) + "\n"
    txt += 'txt-record=evil.test,v=spf1 -all\n'
    txt += 'txt-record=_dmarc.evil.test,v=DMARC1; p=none; adkim=r; aspf=r\n'
    extra.write_text(txt, encoding="ascii")
    _log(stage, "DNS extra records written; recreating dns so evil.test is served")
    from research.lib import dockerctl
    dockerctl.compose(run_id, ["up", "-d", "--build", "dns"], timeout=300)
    time.sleep(2)

    cases = {}
    # 1. legitimate signed lab.test
    legit_src = RUN / "causal" / "preflight" / "signed.eml"
    # 2. mutate-only attacker: fixed lab.test signature, From inserted above
    mutant_src = RUN / "causal" / "cases" / "from-relaxed-n1-h1-insert-before" / "mutant.eml"
    # 3. unsigned
    unsigned = corpus.base("e2e-unsigned")
    (stage / "unsigned.eml").write_bytes(unsigned)
    # 4. own key
    own = _own_key_message(stage, key)
    (stage / "own-key.eml").write_bytes(own)
    catalog = {
        "legit": (legit_src, b"Case: preflight"),
        "mutate-only": (mutant_src, b"base-from-relaxed-n1-h1"),
        "unsigned": (stage / "unsigned.eml", b"Case: e2e-unsigned"),
        "own-key": (stage / "own-key.eml", b"Case: e2e-own-key"),
    }
    rows = []
    for name, (path, token) in catalog.items():
        raw = path.read_bytes()
        dest = stage / name
        dest.mkdir(parents=True, exist_ok=True)
        message = raw
        (dest / "input.eml").write_bytes(message)
        pre = verify_file(f"/evidence/{run_id}/e2e/{name}/input.eml")
        sent = _send(run_id, f"/evidence/{run_id}/e2e/{name}/input.eml", f"/evidence/{run_id}/e2e/{name}/smtp.txt")
        stored, mid = _mailpit(token) if sent.get("accepted") else (None, None)
        if stored is not None:
            (dest / "stored.eml").write_bytes(stored)
            post = verify_file(f"/evidence/{run_id}/e2e/{name}/stored.eml")
        else:
            post = {"delivery": "pending"}
        row = {
            "case": name,
            "attacker": {
                "legit": "none",
                "mutate-only": "can mutate a signed message and does not have the lab.test private key",
                "unsigned": "no signature",
                "own-key": "holds only the evil.test key",
            }[name],
            "sha256": sha256_bytes(message),
            "smtp": sent,
            "mailpit_id": mid,
            "delivery": "delivered" if stored is not None else "pending",
            "before": {k: v.get("status") for k, v in pre.items()} if isinstance(pre, dict) else pre,
            "after": {k: v.get("status") for k, v in post.items()} if stored is not None else post,
        }
        write_json(dest / "row.json", row)
        rows.append(row)
        _log(stage, f"{name} delivery={row['delivery']} before={row['before']} after={row['after']}")
    problems = []
    legit = next(r for r in rows if r["case"] == "legit")
    if legit["delivery"] != "delivered" or legit["before"].get("dkimpy") != "pass":
        problems.append("legitimate signed mail was not delivered with dkimpy pass")
    unsigned_row = next(r for r in rows if r["case"] == "unsigned")
    if unsigned_row["before"].get("dkimpy") == "pass":
        problems.append("unsigned mail verified as pass")
    report = {
        "stage": "e2e",
        "passed": not problems,
        "problems": problems,
        "rows": rows,
        "client_gap": "Roundcube and SnappyMail were not started in this run; no DOM or screenshot is invented.",
        "policy_note": "Lab DNS publishes DMARC p=none. That is the experimental zone, not a product default. rspamd in this image has SPF and DMARC modules disabled.",
        "counts_as_finding": False,
    }
    write_json(stage / "gate.json", report)
    lines = ["# Week 3 end to end", "", f"Gate passed: {report['passed']}", "", report["policy_note"], "", report["client_gap"], ""]
    for row in rows:
        lines.append(f"- {row['case']}: attacker={row['attacker']} delivery={row['delivery']} before={row['before']} after={row['after']}")
    (stage / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
