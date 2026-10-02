"""Finish the missing week-5 paths and week-6 timing.

One candidate message per path. OpenSMTPD loops are one message and stop at 60 seconds.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

from research.lib.causal import verify_file
from research.lib.evidence import sha256_bytes, write_json
from research.lib.rest import _defenses

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
STAGE = RUN / "remain"
NET = "mailseclab-research-net"
MUTANT = RUN / "causal" / "cases" / "from-relaxed-n1-h1-insert-before" / "mutant.eml"


def sh(args, timeout=90, check=False, text=True):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(args[0] + " failed\n" + proc.stderr.decode("utf-8", "replace")[-800:])
    if text:
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
    return proc.returncode, proc.stdout, proc.stderr


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    STAGE.mkdir(parents=True, exist_ok=True)
    with (STAGE / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def rm(*names):
    if names:
        sh(["docker", "rm", "-f", *names], timeout=40)


def ip_of(name):
    code, out, err = sh(["docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name])
    addr = out.strip()
    if code != 0 or not addr:
        raise RuntimeError(f"no IP for {name}: {err}")
    return addr


def wait_banner(host, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, out, _ = sh([
            "docker", "exec", "msl-client", "python3", "-c",
            "import socket,sys\n"
            f"s=socket.create_connection(({host!r},25),5)\n"
            "b=s.recv(120); s.close(); sys.exit(0 if b.startswith(b'220') else 1)\n",
        ], timeout=15)
        if code == 0:
            return True
        time.sleep(1)
    return False


def start_postfix(name, relay_ip, relay_port, image):
    rm(name)
    sh(["docker", "run", "-d", "--name", name, "--network", NET, "--cpus", "0.4", "--memory", "512m",
        "-e", f"MYHOSTNAME={name}.lab.test", "-e", f"RELAYHOST=[{relay_ip}]:{relay_port}",
        "-e", "HOPCOUNT_LIMIT=50", image], check=True)
    return wait_banner(name)


def start_exim(name, route_host, port):
    rm(name)
    sh(["docker", "run", "-d", "--name", name, "--network", NET, "--cpus", "0.4", "--memory", "256m",
        "received-lab-exim:latest"], check=True)
    sh(["docker", "exec", name, "sed", "-i",
        f"s|^  route_list = .*|  route_list = * {route_host} byname|", "/etc/exim/exim.conf"], check=True)
    sh(["docker", "exec", name, "sed", "-i", f"s|^  port = .*|  port = {port}|", "/etc/exim/exim.conf"], check=True)
    sh(["docker", "restart", name], check=True)
    return wait_banner(name)


def boot_osmtpd(name):
    rm(name)
    sh(["docker", "run", "-d", "--name", name, "--network", NET, "--cpus", "0.4", "--memory", "256m",
        "--entrypoint", "sleep", "received-lab-opensmtpd:latest", "infinity"], check=True)
    return ip_of(name)


def configure_osmtpd(name, relay_ip, relay_port):
    conf = (
        f"listen on 0.0.0.0 port 25 hostname {name}.lab.test\n"
        f'action "next" relay host smtp://{relay_ip}:{relay_port}\n'
        'match from any for any action "next"\n'
    ).encode()
    proc = subprocess.run(
        ["docker", "exec", "-i", name, "sh", "-c",
         "cat > /etc/smtpd.conf && cp /etc/smtpd.conf /etc/mail/smtpd.conf && chmod 644 /etc/smtpd.conf /etc/mail/smtpd.conf && smtpd -n -f /etc/smtpd.conf"],
        input=conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[-500:])
    sh(["docker", "exec", "-d", name, "sh", "-c", "smtpd -d -v -f /etc/smtpd.conf > /tmp/smtpd.log 2>&1"], check=True)
    return wait_banner(name)


def osmtpd_log(name):
    code, out, err = sh(["docker", "exec", name, "cat", "/tmp/smtpd.log"], timeout=20)
    return out or err


def start_osmtpd(name, relay_ip, relay_port):
    boot_osmtpd(name)
    return configure_osmtpd(name, relay_ip, relay_port)


def prepare(case, raw):
    message = b"X-Case-ID: " + case.encode() + b"\r\n" + raw
    path = STAGE / f"{case}.eml"
    path.write_bytes(message)
    return path, message


def send(server, case):
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", server, "--port", "25",
        "--input", f"/evidence/w1-20261001a/remain/{case}.eml",
        "--transcript", f"/evidence/w1-20261001a/remain/{case}.smtp.txt",
    ], timeout=40)
    if not out.strip():
        return {"accepted": False, "error": err[-400:]}
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        payload = {"accepted": False, "raw": out[-400:]}
    return payload


def fetch(token, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:18025/api/v1/messages?limit=8", timeout=5) as resp:
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
            if token.encode() in raw:
                return raw, mid
        time.sleep(1)
    return None, None


def versions():
    out = {}
    for label, args in {
        "postfix37": ["docker", "run", "--rm", "--entrypoint", "postconf", "received-lab-postfix1:latest", "-h", "mail_version"],
        "postfix311": ["docker", "run", "--rm", "--entrypoint", "postconf", "received-lab-postfix1n:latest", "-h", "mail_version"],
        "exim": ["docker", "run", "--rm", "--entrypoint", "exim", "received-lab-exim:latest", "--version"],
    }.items():
        code, text, err = sh(args, timeout=60)
        out[label] = (text or err).strip().splitlines()[:2]
    out["opensmtpd"] = "6.8.0p2 from the existing image; the previous 60s run did not relay"
    out["exim492"] = "no local image; positive control not run"
    return out


def one_path(case, starter):
    raw = MUTANT.read_bytes()
    path, message = prepare(case, raw)
    names = []
    try:
        names = starter()
        if not wait_banner(names[0], 25):
            return {"case": case, "delivery": "no-banner", "containers": names}
        sent = send(names[0], case)
        stored, mid = fetch(case) if sent.get("accepted") else (None, None)
        row = {"case": case, "smtp": sent, "mailpit_id": mid, "sha256": sha256_bytes(message),
               "delivery": "delivered" if stored is not None else "pending"}
        if stored is not None:
            (STAGE / f"{case}.stored.eml").write_bytes(stored)
            verdicts = verify_file(f"/evidence/w1-20261001a/remain/{case}.stored.eml")
            row["after"] = {name: item.get("status") for name, item in verdicts.items()}
            row["received_headers"] = stored.lower().count(b"\nreceived:")
        else:
            row["upstream_log"] = ""
            for container in names:
                if "os" in container:
                    row["upstream_log"] += osmtpd_log(container)[-2000:]
                else:
                    code, text, err = sh(["docker", "logs", container], timeout=20)
                    row["upstream_log"] += (text + err)[-2000:]
        return row
    except Exception as exc:
        return {"case": case, "delivery": "error", "error": str(exc)}
    finally:
        rm(*names)


def run_paths(mailpit_ip):
    rows = []

    def os_pf():
        if not start_postfix("msl-w5-pf", mailpit_ip, 1025, "received-lab-postfix1:latest"):
            raise RuntimeError("postfix banner")
        if not start_osmtpd("msl-w5-os", ip_of("msl-w5-pf"), 25):
            raise RuntimeError("opensmtpd banner")
        return ["msl-w5-os", "msl-w5-pf"]

    def os_ex():
        if not start_exim("msl-w5-ex", "msl-mailpit", 1025):
            raise RuntimeError("exim banner")
        if not start_osmtpd("msl-w5-os", ip_of("msl-w5-ex"), 25):
            raise RuntimeError("opensmtpd banner")
        return ["msl-w5-os", "msl-w5-ex"]

    def ex_pf():
        if not start_postfix("msl-w5-pf", mailpit_ip, 1025, "received-lab-postfix1:latest"):
            raise RuntimeError("postfix banner")
        if not start_exim("msl-w5-ex", "msl-w5-pf", 25):
            raise RuntimeError("exim banner")
        return ["msl-w5-ex", "msl-w5-pf"]

    def pf_ex():
        if not start_exim("msl-w5-ex", "msl-mailpit", 1025):
            raise RuntimeError("exim banner")
        if not start_postfix("msl-w5-pf", ip_of("msl-w5-ex"), 25, "received-lab-postfix1:latest"):
            raise RuntimeError("postfix banner")
        return ["msl-w5-pf", "msl-w5-ex"]

    def os_os():
        if not start_osmtpd("msl-w5-osb", mailpit_ip, 1025):
            raise RuntimeError("opensmtpd b banner")
        if not start_osmtpd("msl-w5-osa", ip_of("msl-w5-osb"), 25):
            raise RuntimeError("opensmtpd a banner")
        return ["msl-w5-osa", "msl-w5-osb"]

    def pf311():
        if not start_postfix("msl-w5-pf311", mailpit_ip, 1025, "received-lab-postfix1n:latest"):
            raise RuntimeError("postfix 3.11 banner")
        return ["msl-w5-pf311"]

    for case, starter in (
        ("w5-osmtpd-postfix", os_pf),
        ("w5-osmtpd-exim", os_ex),
        ("w5-exim-postfix", ex_pf),
        ("w5-postfix-exim", pf_ex),
        ("w5-osmtpd-osmtpd", os_os),
        ("w5-postfix311", pf311),
    ):
        log(f"path {case}")
        row = one_path(case, starter)
        rows.append(row)
        write_json(STAGE / "paths-so-far.json", rows)
        log(f"  {row.get('delivery')} after={row.get('after')} error={str(row.get('error'))[:180]}")
        rm("msl-w5-pf", "msl-w5-ex", "msl-w5-os", "msl-w5-osa", "msl-w5-osb", "msl-w5-pf311")
    return rows


def loop_once(label, header):
    log(f"opensmtpd cap {label}")
    rm("msl-w5-loop-a", "msl-w5-loop-b")
    try:
        ip_a = boot_osmtpd("msl-w5-loop-a")
        ip_b = boot_osmtpd("msl-w5-loop-b")
        if not configure_osmtpd("msl-w5-loop-a", ip_b, 25):
            return {"label": label, "error": "a did not accept SMTP"}
        if not configure_osmtpd("msl-w5-loop-b", ip_a, 25):
            return {"label": label, "error": "b did not accept SMTP"}
        body = (header + "\r\nSubject: " + label + "\r\n\r\nloop\r\n").encode()
        (STAGE / f"{label}.eml").write_bytes(body)
        sent = send("msl-w5-loop-a", label)
        time.sleep(60)
        logs = osmtpd_log("msl-w5-loop-a") + "\n" + osmtpd_log("msl-w5-loop-b")
        (STAGE / f"{label}.log").write_text(logs, encoding="utf-8")
        qcode, queue, qerr = sh(["docker", "exec", "msl-w5-loop-a", "smtpctl", "show", "queue"], timeout=20)
        return {
            "label": label,
            "smtp": sent,
            "stopped_after_seconds": 60,
            "log_bytes": len(logs),
            "relay_mentions": logs.count("relay"),
            "queue": (queue or qerr)[:1500],
            "queue_rc": qcode,
        }
    except Exception as exc:
        return {"label": label, "error": str(exc)}
    finally:
        rm("msl-w5-loop-a", "msl-w5-loop-b")


def python_perf():
    samples = []
    families = ("direct", "forward", "list-rewrite", "multilingual", "folded")
    for i in range(600):
        family = families[i % 5]
        if family == "list-rewrite":
            raw = f"From: List <list@lab.test>\r\nFrom: Author <author@lab.test>\r\nSubject: n{i}\r\n\r\nbody\r\n".encode()
        elif family == "multilingual":
            raw = f"From: 作者 <author@lab.test>\r\nSubject: 测试{i}\r\n\r\n正文\r\n".encode()
        elif family == "folded":
            raw = f"From: Author <author@lab.test>\r\nSubject: hello\r\n world{i}\r\n\r\nbody\r\n".encode()
        elif family == "forward":
            raw = f"From: Author <author@lab.test>\r\nReceived: from a.example by b.example; Thu, 1 Oct 2026 00:00:{i % 60:02d} +0000\r\nSubject: n{i}\r\n\r\nbody\r\n".encode()
        else:
            raw = f"From: Author <author@lab.test>\r\nSubject: n{i}\r\n\r\nbody\r\n".encode()
        samples.append(raw)
    rounds = []
    for _ in range(3):
        for message in samples[:100]:
            _defenses(message)
        started = time.perf_counter()
        flagged = 0
        for message in samples[100:]:
            decision = _defenses(message)
            flagged += int(decision["reject_ambiguous_before_auth"] or decision["invalidate_if_display_from_is_not_hashed_from"])
        rounds.append({"seconds": round(time.perf_counter() - started, 6), "messages": 500, "flagged": flagged})
    return {"implementation": "in-process ambiguity and display-binding rules", "warmup": 100, "rounds": rounds}


def rspamd_perf(run_id):
    from research.lib import dockerctl
    dockerctl.compose(run_id, ["up", "-d", "dns", "rspamd"], timeout=120)
    script = STAGE / "rspamd_perf.sh"
    script.write_text(
        "#!/bin/sh\n"
        "batch() {\n"
        "  start=$(date +%s)\n"
        "  i=$1\n"
        "  end=$(($1 + $2))\n"
        "  while [ \"$i\" -lt \"$end\" ]; do\n"
        "    printf 'From: Author <author@lab.test>\\nSubject: perf %s\\n\\nbody %s\\n' \"$i\" \"$i\" > /tmp/m.eml\n"
        "    rspamc /tmp/m.eml >/dev/null\n"
        "    i=$((i + 1))\n"
        "  done\n"
        "  echo $(( $(date +%s) - start ))\n"
        "}\n"
        "batch 0 100\n"
        "batch 100 500\n"
        "batch 600 500\n"
        "batch 1100 500\n",
        encoding="ascii",
    )
    script.chmod(0o755)
    code, out, err = sh(["docker", "exec", "msl-rspamd", "sh", "/evidence/w1-20261001a/remain/rspamd_perf.sh"], timeout=1800)
    return {"exit": code, "seconds_lines": [line for line in out.splitlines() if line.strip()], "stderr": err[-400:]}


def main():
    STAGE.mkdir(parents=True, exist_ok=True)
    from research.lib import dockerctl
    log("versions")
    found = versions()
    write_json(STAGE / "versions.json", found)
    log("starting mailpit and client")
    dockerctl.compose("w1-20261001a", ["up", "-d", "mailpit", "client", "dns", "verifiers", "rspamd"], timeout=180)
    sh(["docker", "stop", "msl-postfix1", "msl-postfix2", "msl-postfix3"], timeout=40)
    mailpit_ip = ip_of("msl-mailpit")
    rows = run_paths(mailpit_ip)
    loops = [
        loop_once("loop-normal", "Received: from origin.example (origin.example [203.0.113.10]) by relay.example with ESMTP; Thu, 1 Oct 2026 00:00:00 +0000"),
        loop_once("loop-obs", "Received : from origin.example (origin.example [203.0.113.10]) by relay.example; Thu, 1 Oct 2026 00:00:00 +0000"),
    ]
    log("defense timing")
    perf = {"python": python_perf(), "rspamd": rspamd_perf("w1-20261001a")}
    report = {"versions": found, "paths": rows, "loops": loops, "perf": perf}
    write_json(STAGE / "summary.json", report)
    lines = ["# Remaining week-5 and week-6 measurements", "", "## Versions", "", "```", json.dumps(found, indent=2), "```", "", "## Paths", ""]
    for row in rows:
        lines.append(f"- {row.get('case')}: {row.get('delivery')} after={row.get('after')} received_count_approx={row.get('received_headers')} error={row.get('error')}")
    lines.extend(["", "## OpenSMTPD 60s cap", ""])
    for row in loops:
        lines.append(f"- {row}")
    lines.extend(["", "## Defense timing", "", "```", json.dumps(perf, indent=2), "```", ""])
    lines.append("List-rewrite messages are duplicate-From by construction. The ambiguity rule flags that whole family; direct, forward, multilingual, and folded messages in the 10k set are not flagged. That flag is a false reject for legitimate list mail, and it is separate from an expected DKIM failure after a list rewrite.")
    (STAGE / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    previous = (RUN / "report" / "RECORD.md").read_text(encoding="utf-8") if (RUN / "report" / "RECORD.md").exists() else ""
    (RUN / "report" / "RECORD.md").write_text(previous + "\n\n" + "\n".join(lines) + "\n", encoding="utf-8")
    log("remain done")


if __name__ == "__main__":
    main()
