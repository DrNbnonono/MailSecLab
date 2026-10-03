"""hdrfuzz v2: enriched grammar (multi-instance From x new address forms) at
chain speed. Known-outcome tuples are loaded from all previous run rows so
only genuinely new combinations count. Stores full per-case evidence.
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
from research.lib.evidence import sha256_bytes

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "hdrfuzz2"
EVIDENCE = "/evidence/w2-20261002a/hdrfuzz2"
VICTIM = "xn--mnchen-3ya.lab.test"
NFC = "m\u00fcnchen.lab.test"
NFD = "mu\u0308nchen.lab.test"

DOMAINS = [
    ("ascii", "lab.test"),
    ("victim-a", VICTIM),
    ("victim-u-nfc", NFC),
    ("victim-u-nfd", NFD),
    ("dot", VICTIM + "."),
    ("upper", VICTIM.upper()),
    ("dotless", "labtest"),
]
# 形态池：每项 (form, weight-ish 靠重复实现)
FORMS = [
    "angle", "angle", "angle",            # 常规，压舱
    "bare",
    "group-one", "group-empty", "group-two",
    "domain-literal",
    "quoted-local",
    "route-addr",                          # RFC 822 obs 路由
    "empty-addr",                          # <>
    "folded-empty-first",                  # From:\r\n <addr>
    "comment-before-domain",
    "comment-after-domain",
]
DISPLAYS = [None, "Bank Security", "=?utf-8?B?5L2g5aW9?="]
CASES = ["From", "from", "FROM"]


def compose(form: str, domain: str, display, rng) -> bytes:
    d = display + " " if display else ""
    if form == "angle":
        return f"{d}<security@{domain}>".encode("utf-8")
    if form == "bare":
        return f"security@{domain}".encode("utf-8")
    if form == "group-one":
        return f"{display or 'Bank'}: security@{domain};".encode("utf-8")
    if form == "group-empty":
        return f"{display or 'Bank'}:;".encode("utf-8")
    if form == "group-two":
        return f"{display or 'Bank'}: security@{domain}, agent@lab.test;".encode("utf-8")
    if form == "domain-literal":
        return f"{d}<security@[203.0.113.7]>".encode("utf-8")
    if form == "quoted-local":
        return f'{d}<"security"@{domain}>'.encode("utf-8")
    if form == "route-addr":
        return f"{d}<@relay.lab.test:security@{domain}>".encode("utf-8")
    if form == "empty-addr":
        return f"{d}<>".encode("utf-8")
    if form == "folded-empty-first":
        return f"\r\n <security@{domain}>".encode("utf-8")  # 拼在 "From:" 后
    if form == "comment-before-domain":
        return f"{d}<security@(Bank){domain}>".encode("utf-8")
    if form == "comment-after-domain":
        return f"{d}<security@{domain} (Bank)>".encode("utf-8")
    raise ValueError(form)


def make_from_line(form: str, domain: str, display, obs: bool, case: str, rng) -> bytes:
    if form == "folded-empty-first":
        return case.encode() + b":\r\n <security@" + domain.encode("utf-8") + b">"
    colon = " :" if obs else ": "
    return case.encode() + colon.encode() + compose(form, domain, display, rng)


def generate(rng: random.Random) -> dict:
    n_from = rng.choices([1, 2, 3], weights=[6, 3, 1])[0]
    instances = []
    for _ in range(n_from):
        dkind, domain = rng.choice(DOMAINS)
        instances.append({
            "form": rng.choice(FORMS), "domain_kind": dkind,
            "display": rng.choice(DISPLAYS), "obs": rng.random() < 0.25,
            "case": rng.choice(CASES), "domain": domain,
        })
    extra = rng.choice([None, None, "sender", "reply-to", "sender-obs"])
    return {"instances": instances, "extra": extra}


def build(case_id: str, spec: dict) -> bytes:
    headers = []
    for inst in spec["instances"]:
        headers.append(make_from_line(inst["form"], inst["domain"], inst["display"], inst["obs"], inst["case"], None))
    headers.append(b"To: bob@lab.test")
    headers.append(b"Date: Sat, 3 Oct 2026 09:00:00 +0000")
    headers.append(b"Subject: hdrfuzz2 probe")
    headers.append(f"Message-ID: <{case_id}@lab.test>".encode())
    headers.append(f"X-Case-ID: {case_id}".encode())
    if spec["extra"] == "sender":
        headers.append(b"Sender: Agent <agent@lab.test>")
    elif spec["extra"] == "sender-obs":
        headers.append(b"Sender : Agent <agent@lab.test>")
    elif spec["extra"] == "reply-to":
        headers.append(b"Reply-To: Reply <reply@evil.test>")
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
    open(f"/evidence/w2-20261002a/hdrfuzz2/{case}.stored.eml", "wb").write(raw)
    ars = [l.decode("utf-8", "replace").strip() for l in raw.split(b"\r\n") if b"Authentication-Results" in l]
    out = {"found": True, "uid": item.decode(), "ar": ars, "envelope": repr(env[0])}
    break
m.logout()
print(json.dumps(out))
'''


def fetch_stored(case_id: str, tries: int = 6, delay: float = 1.0):
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
RSPAMD_DMARC_RE = re.compile(r"(DMARC_POLICY_[A-Z_]+)")



def _has_member(env_repr: str) -> bool:
    return bool(re.search(r'\(\(?"[^"]*" NIL "[^"]+" "(?!NIL)[^")]+("\]|")', env_repr)) or bool(re.search(r'NIL NIL "[^"]+" "[^")\]]+\)?', env_repr))


def envelope_class(env_repr: str) -> str:
    if not env_repr:
        return "unknown"
    head = env_repr[:80]
    if head.split('"')[0].strip().startswith("(b'") :
        head = env_repr
    if "NIL NIL NIL NIL" in env_repr[:120] or re.match(r".*ENVELOPE \([^)]* NIL \(\(", env_repr) and "NIL" in head[:60]:
        pass
    if "[203" in env_repr:
        return "literal"
    if "\\xfc" in env_repr or "\u00fc" in env_repr or "u\u0308" in env_repr or "xc3" in env_repr or "x CC" in env_repr:
        return "utf8"
    if "MISSING_MAILBOX" in env_repr:
        return "missing"
    # 群组名标记 ((NIL NIL display NIL)(member)...) 不是 nil From
    if env_repr.count("NIL NIL NIL NIL") >= 1 and "((" in env_repr[:160] and not _has_member(env_repr):
        return "nil"
    if VICTIM in env_repr:
        return "victim"
    if "lab.test" in env_repr:
        return "labtest"
    return "other"


def rspamd_dmarc(case_id: str) -> str:
    code, out, _ = sh(["docker", "exec", "msl-rspamd", "sh", "-c",
                       f"grep 'id: <{case_id}@lab.test>' /var/log/rspamd/rspamd.log | grep write_log | tail -1"], timeout=30)
    line = out.strip()
    if not line:
        return "absent"
    m = RSPAMD_DMARC_RE.search(line)
    return m.group(1) if m else "no-dmarc-sym"


def outcome(row: dict) -> tuple:
    ar_text = " ".join(row.get("ar") or [])
    dmarc = DMARC_RE.search(ar_text)
    od = dmarc.group(1) if dmarc else "absent"
    hf = HEADERFROM_RE.search(ar_text)
    hf_v = (hf.group(1) if hf else "") or "empty"
    hf_kind = "empty" if hf_v == "empty" else ("utf8" if not hf_v.isascii() else "ascii")
    env = row.get("env_class")
    return (row["smtp_code"], row["delivered"], od, hf_kind, row["rspamd"], env)


def classify(out: tuple) -> list[str]:
    smtp, delivered, od, hf_kind, rsp, env = out
    od_consults = od not in ("none", "absent")
    rs_consults = rsp not in ("absent", "no-dmarc-sym")
    classes = []
    if od_consults != rs_consults:
        classes.append("policy_split")
    if od == "absent" and delivered:
        classes.append("no_stamp")
    if hf_kind == "empty" and delivered:
        classes.append("empty_identity_ar")
    if env == "nil" and delivered:
        classes.append("nil_envelope")
    if env == "unknown" and delivered:
        classes.append("unknown_envelope")
    if od == "none" and delivered and rs_consults:
        classes.append("odmarc_void_only")
    if rsp in ("absent", "no-dmarc-sym") and delivered and od_consults:
        classes.append("rspamd_void_only")
    return sorted(set(classes)) or ["none"]


def load_known() -> set:
    known = set()
    for pattern in [RUN / "hdrfuzz2" / "known-outcomes.json", RUN / "hdrfuzz" / "rows-seed7.json"]:
        if not pattern.exists():
            continue
        data = json.loads(pattern.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("rows", [])
        for r in rows:
            if "outcome" in r:
                known.add(tuple(r["outcome"]))
            elif "sig" in r and "smtp_code" in r:
                known.add((r.get("smtp_code"), r.get("delivered"),
                           r["sig"].get("odmarc"), r["sig"].get("odmarc_hf"),
                           r.get("rspamd_dmarc"), r["sig"].get("env")))
    # 手工种子（战役 V / eai / void 的代表组合）
    for t in [
        ("250", True, "fail", "ascii", "DMARC_POLICY_REJECT", "victim"),
        ("250", True, "none", "utf8", "DMARC_POLICY_REJECT", "utf8"),
        ("250", True, "none", "empty", "no-dmarc-sym", "literal"),
        ("250", True, "absent", "ascii", "no-dmarc-sym", "nil"),
        ("250", True, "fail", "ascii", "no-dmarc-sym", "victim"),
        ("250", True, "none", "utf8", "no-dmarc-sym", "utf8"),
        ("250", True, "fail", "utf8", "DMARC_POLICY_REJECT", "utf8"),
    ]:
        known.add(t)
    return known


def run_chunk(n_cases: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for i in range(n_cases):
        spec = generate(rng)
        forms = "+".join(inst["form"] for inst in spec["instances"])
        case_id = f"h2-{seed}-{i:03d}"
        raw = build(case_id, spec)
        path = STAGE / f"{case_id}.eml"
        path.write_bytes(raw)
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
        row = {
            "case": case_id,
            "forms": forms,
            "spec": [{k: (v if isinstance(v, (str, bool)) else str(v)) for k, v in inst.items()} for inst in spec["instances"]],
            "extra": spec["extra"],
            "from_line_preview": raw[:raw.find(b"\r\nTo")].decode("utf-8", "replace")[:160],
            "smtp": sent.get("reply"), "smtp_code": (sent.get("reply") or "")[:3],
            "delivered": stored.get("found"),
            "ar": stored.get("ar", []),
            "envelope": (stored.get("envelope") or "")[:260],
            "rspamd": rspamd_dmarc(case_id),
            "sha256": sha256_bytes(raw),
        }
        row["env_class"] = envelope_class(row["envelope"])
        row["outcome"] = list(outcome(row))
        row["classes"] = classify(tuple(row["outcome"]))
        rows.append(row)
    return rows


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    STAGE.mkdir(parents=True, exist_ok=True)
    known = load_known()
    t0 = time.time()
    rows = run_chunk(n, seed)
    new_rows = [r for r in rows if tuple(r["outcome"]) not in known]
    payload = {"seed": seed, "n": n, "seconds": round(time.time() - t0, 1),
               "new_outcome_count": len(new_rows),
               "known_size": len(known),
               "rows": rows}
    (STAGE / f"rows-seed{seed}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    seen_new = {}
    for r in new_rows:
        key = tuple(r["outcome"])
        seen_new.setdefault(key, []).append(r["case"] + "|" + r["forms"])
    print(json.dumps({"seed": seed, "n": n, "seconds": payload["seconds"],
                      "divergent": sum(1 for r in rows if r["classes"] != ["none"]),
                      "new_outcomes": {str(k): v[:3] for k, v in seen_new.items()}}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
