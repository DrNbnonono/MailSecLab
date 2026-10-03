"""Task 6: DKIM verifiers x obs-colon Received cross matrix.

Three signed baselines (h=from:to:subject:date:received, d=lab.test, cal):
  s0-strict-signed  3 strict Received present at sign time
  s1-obs-signed     3 `Received :` present at sign time (hash over obs bytes)
  s2-obs-injected   signed over 3 strict, then ONE obs line inserted at top
                    (signature bytes unchanged - replay-capable mutation)

Arms: norelay (file bytes), osmtpd, postfix (rcpt=capture@ -> mailpit raw).
Verifiers: dkimpy / perl / go / rspamd via research.lib.causal.verify_file.
Known anchors: KB2 family (post-sign injected -> dkimpy reject, perl/go pass,
rspamd ALLOW). New cells: s1 four-way on obs-signed bytes; s2 four-way AFTER
relay (does osmtpd's obs-preservation carry dkimpy's rejection into the box).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")
from research import reference, structure
from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes
from research.lib.tracefacts import facts as trace_facts

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w3-20261003a")
STAGE = RUN / "sigprobe2"
EVIDENCE = "/evidence/w3-20261003a/sigprobe2"
KEY = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/keys/priv.pem")
H = ["from", "to", "subject", "date", "received"]

STRICT = "Received: from h{i}.lab.test (h{i}.lab.test [203.0.113.{i}]) by h{i}x.lab.test with ESMTP id S{i}; Sat, 03 Oct 2026 22:0{i}:00 +0000"
OBS = "Received : from h{i}.lab.test (h{i}.lab.test [203.0.113.{i}]) by h{i}x.lab.test with ESMTP id O{i}; Sat, 03 Oct 2026 22:1{i}:00 +0000"



def sign_custom(raw: bytes) -> bytes:
    import base64
    import hashlib
    info = structure.inspect(raw)
    body = reference.canonical_body(raw[info["boundary"] + 4:], "relaxed")
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = (b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=lab.test;\r\n s=cal; h="
                 + ":".join(H).encode() + b";\r\n bh=" + bh + b"; b=\r\n")
    hashed, _ = reference.hashing_input(raw, signature, H, "relaxed")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b"\r\n"
    return signature + raw


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def build_case(name: str, received_tpl: str) -> bytes:
    case_id = "sp2-" + name
    head = "\r\n".join(received_tpl.format(i=i) for i in range(3)).encode()
    return (head + b"\r\n"
            + b"From: Bank Security <security@lab.test>\r\n"
            + b"To: bob@lab.test\r\n"
            + b"Date: Sat, 3 Oct 2026 22:30:00 +0000\r\n"
            + f"Subject: sigprobe2 {name}\r\n".encode()
            + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
            + f"X-Case-ID: {case_id}\r\n".encode()
            + b"\r\nPlease confirm the payment.\r\n")


FETCH_SCRIPT = '''
import json, sys, time, urllib.request
token, marker, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
time.sleep(2)
for _ in range(10):
    try:
        r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=50", timeout=5)
        hits = [m for m in json.loads(r.read()).get("messages", [])
                if token in (m.get("Subject") or "")]
        cands = []
        for m in hits:
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
            if marker.encode() in raw and token.encode() in raw:
                cands.append((m.get("Created") or "", raw))
        if cands:
            cands.sort(key=lambda x: x[0], reverse=True)
            open(out_path, "wb").write(cands[0][1])
            print("OK", len(cands[0][1])); sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
'''


def fetch_stored(token: str, marker: str, out_name: str) -> bytes | None:
    for _ in range(3):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                           token, marker, f"{EVIDENCE}/{out_name}.stored.eml"],
                          timeout=60, stdin=FETCH_SCRIPT.encode())
        if out.strip().startswith("OK"):
            return (STAGE / f"{out_name}.stored.eml").read_bytes()
        time.sleep(1)
    return None


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    baselines = {}
    # s0 / s1：对各自语料签名（sign_custom 不做 modern 校验，obs 语料可签）
    for name, tpl in (("s0-strict-signed", STRICT), ("s1-obs-signed", OBS)):
        base = build_case(name, tpl)
        signed = sign_custom(base)
        baselines[name] = signed
        (STAGE / f"{name}.eml").write_bytes(signed)
    # s2：独立 case（自己的 Subject/X-Case-ID）对 strict 形态签名后，顶部插 obs。
    # 不能从 s0 字节构造——否则 Subject 沿用 s0，mailpit 里两臂无法区分。
    s2_signed = sign_custom(build_case("s2-obs-injected", STRICT))
    obs_line = OBS.format(i=9).encode() + b"\r\n"
    s2 = obs_line + s2_signed
    baselines["s2-obs-injected"] = s2
    (STAGE / "s2-obs-injected.eml").write_bytes(s2)

    rows = []
    for name, raw in baselines.items():
        case_id = "sp2-" + name
        for path in ("norelay", "osmtpd", "postfix"):
            if path == "norelay":
                stored = raw
                stored_path = f"{EVIDENCE}/{name}.eml"
            else:
                send_name = f"{name}-{path}"
                (STAGE / f"{send_name}.eml").write_bytes(raw)
                server = "opensmtpd" if path == "osmtpd" else "msl-auth-postfix"
                code, out, err = sh([
                    "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
                    "--server", server, "--port", "25",
                    "--mail-from", "alice@lab.test", "--rcpt-to", "capture@lab.test",
                    "--input", f"{EVIDENCE}/{send_name}.eml",
                    "--transcript", f"{EVIDENCE}/{send_name}.smtp.txt",
                ], timeout=90)
                try:
                    sent = json.loads(out)
                except json.JSONDecodeError:
                    sent = {"accepted": False}
                marker = "by opensmtpd" if path == "osmtpd" else "by auth-postfix"
                stored = fetch_stored(f"sigprobe2 {name}", marker, send_name) if sent.get("accepted") else None
                if stored is None:
                    rows.append({"baseline": name, "path": path, "smtp": sent.get("reply"),
                                 "stored": False})
                    print(json.dumps({"b": name, "p": path, "stored": False}), flush=True)
                    continue
                stored_path = f"{EVIDENCE}/{send_name}.stored.eml"
            verdicts = verify_file(stored_path)
            row = {
                "baseline": name, "path": path, "stored": True,
                "verifiers": {k: v.get("status") for k, v in verdicts.items()},
                "rspamd_action": (verdicts.get("rspamd") or {}).get("action"),
                "facts": trace_facts(stored)["received"],
                "input_sha256": sha256_bytes(raw),
            }
            rows.append(row)
            print(json.dumps({"b": name, "p": path, "v": row["verifiers"],
                              "f": row["facts"]}), flush=True)
            time.sleep(1)
    (STAGE / "matrix.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    lines_out = ["baseline,path,dkimpy,perl,go,rspamd,received_facts"]
    for r in rows:
        v = r.get("verifiers") or {}
        cells = [r["baseline"], r["path"]] + [str(v.get(k)) for k in ("dkimpy", "perl", "go", "rspamd")]
        cells.append(json.dumps(r.get("facts") or {}).replace(chr(34), "'"))
        lines_out.append(",".join(cells))
    (STAGE / "matrix.csv").write_text(chr(10).join(lines_out) + chr(10), encoding="utf-8")


if __name__ == "__main__":
    main()
