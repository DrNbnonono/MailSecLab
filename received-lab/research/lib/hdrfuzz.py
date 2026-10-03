"""hdrfuzz v1: grammar-guided differential fuzzer for email identity headers.

Generation axis: From field form grammar (display-name x addr-form x domain
form x obs-colon x case) plus identity-field extras. Oracle: the receiving
chain itself - SMTP outcome, OpenDMARC AR (verdict + header.from), rspamd
milter DMARC symbols, delivery, IMAP ENVELOPE. Divergences are signed by
security-relevant derived values, deduplicated against a table of classes
already known from hand campaigns (w1 K-series, w2 EAI/void campaigns).

Ablation arm: w1-style random byte mutation with the w1 oracle (file
verifiers only), same case budget, for the method comparison.
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "hdrfuzz"
EVIDENCE = "/evidence/w2-20261002a/hdrfuzz"

VICTIM = "xn--mnchen-3ya.lab.test"
NFC = "m\u00fcnchen.lab.test"
NFD = "m\u0308nchen.lab.test".replace("u\u0308", "u\u0308")

DISPLAY = [None, "Bank Security", "\u4f5c\u8005", "=?utf-8?B?5L2g5aW9?="]
DOMAINS = [
    ("ascii-control", "lab.test"),
    ("victim-alabel", VICTIM),
    ("victim-ulabel-nfc", NFC),
    ("victim-ulabel-nfd", "mu\u0308nchen.lab.test"),
    ("trailing-dot", VICTIM + "."),
    ("upper", VICTIM.upper()),
]
ADDR_FORMS = ["angle", "bare", "group-one", "group-empty", "group-two", "domain-literal", "quoted-local"]
CASES_FORMS = ["From", "from", "FROM"]
OBS_COLON = [False, True]
EXTRAS = [None, "sender", "reply-to"]


def compose_addr(form: str, local: str, domain: str, display: str | None) -> bytes:
    if form == "angle":
        prefix = f"{display} " if display else ""
        return f"{prefix}<{local}@{domain}>".encode("utf-8")
    if form == "bare":
        return f"{local}@{domain}".encode("utf-8")
    if form == "group-one":
        return f"{display or 'Group'}: {local}@{domain};".encode("utf-8")
    if form == "group-empty":
        return f"{display or 'Group'}:;".encode("utf-8")
    if form == "group-two":
        return f"{display or 'Group'}: {local}@{domain}, agent@lab.test;".encode("utf-8")
    if form == "domain-literal":
        prefix = f"{display} " if display else ""
        return f"{prefix}<{local}@[203.0.113.7]>".encode("utf-8")
    if form == "quoted-local":
        prefix = f"{display} " if display else ""
        return f'{prefix}<"{local}"@{domain}>'.encode("utf-8")
    raise ValueError(form)


def generate(rng: random.Random) -> dict:
    display = rng.choice(DISPLAY)
    dkind, domain = rng.choice(DOMAINS)
    form = rng.choice(ADDR_FORMS)
    case = rng.choice(CASES_FORMS)
    obs = rng.choice(OBS_COLON)
    extra = rng.choice(EXTRAS)
    colon = " :" if obs else ": "
    from_line = case.encode() + colon.encode() + compose_addr(form, "security", domain, display)
    return {"display": display, "domain_kind": dkind, "addr_form": form, "case": case, "obs": obs,
            "extra": extra, "from_line": from_line}


def build(case_id: str, spec: dict) -> bytes:
    headers = [spec["from_line"], b"To: bob@lab.test",
               b"Date: Fri, 2 Oct 2026 19:00:00 +0000",
               b"Subject: hdrfuzz probe",
               f"Message-ID: <{case_id}@lab.test>".encode(),
               f"X-Case-ID: {case_id}".encode()]
    if spec["extra"] == "sender":
        headers.insert(1, b"Sender: Agent <agent@lab.test>")
    elif spec["extra"] == "reply-to":
        headers.insert(1, b"Reply-To: Reply <reply@evil.test>")
    return b"\r\n".join(headers) + b"\r\n\r\nPlease confirm the payment.\r\nCase: " + case_id.encode() + b"\r\n"


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


FETCH_SCRIPT = r'''
import imaplib, json, sys
case = sys.argv[1]
m = imaplib.IMAP4("msl-dovecot", 143)
m.login("bob", "lab-bob")
m.select("INBOX", readonly=True)
typ, data = m.search(None, "ALL")
out = {"found": False}
for item in reversed(data[0].split()):
    typ, msg = m.fetch(item, "(BODY.PEEK[HEADER.FIELDS (X-CASE-ID)])")
    blob = (msg[0][1] or b"") if msg and msg[0] else b""
    if case.encode() not in blob:
        continue
    typ, env = m.fetch(item, "(ENVELOPE)")
    typ, full = m.fetch(item, "(BODY.PEEK[])")
    raw = full[0][1]
    open(f"/evidence/w2-20261002a/hdrfuzz/{case}.stored.eml", "wb").write(raw)
    ars = [l.decode("utf-8", "replace").strip() for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "ar": ars, "envelope": repr(env[0])}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 6, delay: float = 2.0):
    last = {"found": False}
    for _ in range(tries):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-", case_id],
                          timeout=60, stdin=FETCH_SCRIPT.encode())
        try:
            last = json.loads(out)
        except json.JSONDecodeError:
            last = {"found": False}
        if last.get("found"):
            return last
        time.sleep(delay)
    return last


DMARC_RE = re.compile(r"dmarc=(\w+)")
HEADERFROM_RE = re.compile(r"header\.from=([^ ]*)")
RSPAMD_DMARC_RE = re.compile(r"(DMARC_POLICY_[A-Z_]+)\([^)]*\)\{([^ }]*)")


def envelope_domain_class(env_repr: str) -> str:
    if env_repr == "NIL" or "NIL NIL NIL" in env_repr[:60]:
        return "nil"
    if "[203" in env_repr:
        return "literal"
    if "\\xfc" in env_repr or "m\\xc3\\xbc" in env_repr or "m\u00fc" in env_repr or "mu\u0308" in env_repr:
        return "utf8"
    if VICTIM in env_repr:
        return "victim"
    if "lab.test" in env_repr:
        return "labtest"
    return "other"


def classify(row: dict) -> dict:
    """Divergence signature over security-relevant derived values."""
    ar_text = " ".join(row.get("ar") or [])
    dmarc = DMARC_RE.search(ar_text)
    od_v = dmarc.group(1) if dmarc else "absent"
    hf = HEADERFROM_RE.search(ar_text)
    hf_v = (hf.group(1) if hf else "") or "empty"
    rsp = row.get("rspamd_dmarc") or "absent"
    env = row.get("env_class") or "?"
    sig = {
        "odmarc": od_v,
        "odmarc_hf": "empty" if hf_v == "empty" else ("utf8" if hf_v and not hf_v.isascii() else "ascii"),
        "rspamd": rsp,
        "env": env,
        "delivered": row.get("delivered"),
        "smtp": "reject" if row.get("smtp_code") and str(row.get("smtp_code")).startswith(("4", "5")) else "accept",
    }
    classes = []
    od_consults = od_v not in ("none", "absent")
    rs_consults = rsp not in ("absent",)
    if od_consults != rs_consults:
        classes.append("policy_split")
    if od_v == "absent" and sig["delivered"]:
        classes.append("no_stamp")
    if sig["odmarc_hf"] == "empty" and sig["delivered"]:
        classes.append("empty_identity_ar")
    if env == "nil" and sig["delivered"]:
        classes.append("nil_envelope")
    if od_v == "none" and sig["delivered"] and rs_consults:
        classes.append("odmarc_void_only")
    if rsp == "absent" and sig["delivered"] and od_consults:
        classes.append("rspamd_void_only")
    sig["classes"] = sorted(set(classes)) or ["none"]
    return sig


# 已知类：手工战役已覆盖的（不计数为新发现）
KNOWN = {
    "odmarc_void_only+policy_split": "U-label/NFD/domain-literal/群组外（w2 eai+void）",
    "rspamd_void_only+policy_split": "群组语法（w2 void v1/v2/v8）",
    "no_stamp+nil_envelope": "空群组/obs-only（w2 void v2/v6）",
    "empty_identity_ar": "domain-literal（w2 void v3）",
}


def rspamd_line(case_id: str) -> str | None:
    code, out, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                       f"grep 'id: <{case_id}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
    return out.strip() or None


def run_grammar(n_cases: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for i in range(n_cases):
        spec = generate(rng)
        case_id = f"hf-{seed}-{i:03d}-{spec['addr_form']}-{spec['domain_kind']}"
        raw = build(case_id, spec)
        (STAGE / f"{case_id}.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", f"{EVIDENCE}/{case_id}.eml",
            "--transcript", f"{EVIDENCE}/{case_id}.smtp.txt",
        ], timeout=60)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-150:]}
        stored = fetch_stored(case_id) if sent.get("accepted") else {"found": False}
        line = rspamd_line(case_id)
        rsp_dmarc = "absent"
        if line:
            m = RSPAMD_DMARC_RE.search(line)
            if m:
                rsp_dmarc = m.group(1)
        row = {
            "case": case_id, "spec": {k: str(v) for k, v in spec.items() if k != "from_line"},
            "from_line": spec["from_line"].decode("utf-8", "replace"),
            "smtp": sent.get("reply"), "smtp_code": (sent.get("reply") or "")[:3],
            "delivered": stored.get("found"),
            "ar": stored.get("ar", []),
            "envelope": (stored.get("envelope") or "")[:200],
            "rspamd_dmarc": rsp_dmarc,
            "sha256": sha256_bytes(raw),
        }
        row["sig"] = classify(row)
        rows.append(row)
        print(json.dumps({"case": case_id.split('-', 2)[-1], "smtp": row["smtp_code"],
                          "delivered": row["delivered"], "sig": row["sig"]["classes"]}, ensure_ascii=False), flush=True)
    return rows


def run_ablation(n_cases: int, seed: int) -> dict:
    """w1-style arm: random byte mutation, file-verifier oracle, no chain."""
    rng = random.Random(seed)
    seed_path = RUN.parent / "w1-20261001a" / "causal" / "preflight" / "signed.eml"
    parent = seed_path.read_bytes()
    info = structure.inspect(parent)
    sigf = next(f for f in info["fields"] if f["name"] == "dkim-signature")
    seen = valid = 0
    splits = 0
    classes = set()
    while seen < n_cases * 6 and len(classes) < n_cases:
        buf = bytearray(parent)
        spots = [i for i in range(0, info["boundary"]) if not (sigf["start"] <= i < sigf["end"])]
        if not spots:
            break
        buf[rng.choice(spots)] = rng.randrange(33, 127)
        mutant = bytes(buf)
        seen += 1
        if structure.field_bytes(mutant, "dkim-signature") != structure.field_bytes(parent, "dkim-signature"):
            continue
        minfo = structure.inspect(mutant)
        if minfo["boundary"] < 0 or "bare-lf" in minfo["issues"]:
            continue
        valid += 1
        path = STAGE / f"abl-current.eml"
        path.write_bytes(mutant)
        verdicts = verify_file(f"{EVIDENCE}/abl-current.eml")
        statuses = {k: v.get("status") for k, v in verdicts.items()}
        classes.add(tuple(sorted(statuses.items())))
        if len(set(statuses.values())) > 1:
            splits += 1
    return {"arm": "byte+file-oracle", "seen": seen, "valid": valid, "splits": splits,
            "status_classes": len(classes)}


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    STAGE.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    rows = run_grammar(n, seed)
    grammar_new = [r for r in rows if any(c not in ("none",) for c in r["sig"]["classes"])]
    # 去重已知类
    for r in grammar_new:
        r["sig"]["known"] = any(
            all(k in r["sig"]["classes"] for k in known.split("+"))
            for known in KNOWN
        ) or r["sig"]["classes"] == ["none"]
    new_rows = [r for r in grammar_new if not r["sig"].get("known")]
    ablation = run_ablation(n, seed)
    report = {
        "tool": "hdrfuzz-v1",
        "seed": seed,
        "grammar_cases": len(rows),
        "seconds": round(time.time() - t0, 1),
        "divergent": len(grammar_new),
        "new_after_known_dedup": len(new_rows),
        "ablation": ablation,
        "known_table": KNOWN,
    }
    (STAGE / f"report-seed{seed}.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    (STAGE / f"rows-seed{seed}.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("grammar_cases", "seconds", "divergent", "new_after_known_dedup", "ablation")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
