"""D-line: adversarial _dmarc policy records (attacker-controlled DNS content)
against the OpenDMARC C parser and rspamd Lua parser.

All record forms are published under distinct subdomains in one DNS update;
each case sends one mail whose From domain carries that record. Crash oracle:
milter liveness after each send + a healthy canary mail at the end.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a")
STAGE = RUN / "dmarcfuzz"

RECORDS = {
    "d01-p-only": "v=DMARC1; p=",
    "d02-dup-p-none-reject": "v=DMARC1; p=none; p=reject",
    "d03-dup-p-reject-none": "v=DMARC1; p=reject; p=none",
    "d04-pct-overflow": "v=DMARC1; p=reject; pct=99999999999999999999",
    "d05-pct-negative": "v=DMARC1; p=reject; pct=-1",
    "d06-pct-huge-hex": "v=DMARC1; p=reject; pct=0x7fffffff",
    "d07-sp-no-p": "v=DMARC1; sp=reject",
    "d08-adkim-dup": "v=DMARC1; p=reject; adkim=s; adkim=r",
    "d09-unknown-tags": "v=DMARC1; p=reject; xyz=abc; aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1",
    "d10-rua-many": "v=DMARC1; p=reject; rua=" + ",".join("mailto:r%d@evil.test" % i for i in range(30)),
    "d11-rua-weird": "v=DMARC1; p=reject; rua=mailto:<>@!#$%&*()",
    "d12-long-record": "v=DMARC1; p=reject; " + "x" * 3800,
    "d13-no-v": "p=reject",
    "d14-v-case": "v=dMaRc1; p=reject",
    "d15-p-junk": "v=DMARC1; p=reject (junk); qua=none",
}


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def milter_up() -> bool:
    code, _, _ = sh(["docker", "exec", "msl-client", "python3", "-c",
                     "import socket; s=socket.create_connection(('msl-opendmarc',8893),timeout=3); s.close()"], timeout=15)
    return code == 0


def send(name: str, case_id: str) -> dict:
    raw = (f"From: Probe <security@{name}.dmarc-p.test>\r\n".encode()
           + b"To: bob@lab.test\r\n"
           b"Date: Sat, 3 Oct 2026 20:00:00 +0000\r\n"
           + ("Subject: dmarc rec %s\r\n" % name).encode()
           + ("Message-ID: <%s@lab.test>\r\n" % case_id).encode()
           + ("X-Case-ID: %s\r\n" % case_id).encode()
           + b"\r\nbody\r\n")
    (STAGE / f"{name}.eml").write_bytes(raw)
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", "msl-auth-postfix", "--port", "25",
        "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
        "--input", f"/evidence/w2-20261002a/dmarcfuzz/{name}.eml",
        "--transcript", f"/evidence/w2-20261002a/dmarcfuzz/{name}.smtp.txt",
    ], timeout=60)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"accepted": False, "raw": (out or err)[-150:]}


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, (name, record) in enumerate(RECORDS.items()):
        case_id = "dmf-" + name
        sent = send(name, case_id)
        alive = milter_up()
        row = {"case": name, "record": record[:80] + ("..." if len(record) > 80 else ""),
               "smtp": sent.get("reply"), "smtp_code": (sent.get("reply") or "")[:3],
               "milter_after": alive}
        rows.append(row)
        print(json.dumps({"case": name, "code": row["smtp_code"], "milter": alive}), flush=True)
        time.sleep(1.2)
        if not alive:
            print("!!! MILTER DOWN after", name, "- restarting probe halted", flush=True)
            break
    # canary：健康邮件验证链路仍正常
    code, out, _ = sh(["docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
                       "--server", "msl-auth-postfix", "--port", "25",
                       "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
                       "--input", "/evidence/w2-20261002a/void/vc-plain-control.eml",
                       "--transcript", "/evidence/w2-20261002a/dmarcfuzz/canary.smtp.txt"], timeout=60)
    rows.append({"case": "canary", "smtp_code": out[:3], "milter_after": milter_up()})
    (STAGE / "cases.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(rows[-1]), flush=True)


if __name__ == "__main__":
    main()
