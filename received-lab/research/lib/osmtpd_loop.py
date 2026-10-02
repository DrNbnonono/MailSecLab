"""Two OpenSMTPD relays pointed at each other.

One run seeds a normal Received line. The other seeds Received with a space
before the colon. Stop on the first 5.4.6, or when accepted deliveries pass
the hop cap. The clock is only a safety stop.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a")
STAGE = RUN / "osmtpd-loop"
NET = "mailseclab-research-net"
SAFETY_SECONDS = 180
ACCEPT_CAP = 160


def sh(args, timeout=60, check=False, input_bytes=None):
    proc = subprocess.run(
        args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[-800:])
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    STAGE.mkdir(parents=True, exist_ok=True)
    with (STAGE / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def ip_of(name):
    code, out, err = sh(["docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name])
    addr = out.strip()
    if code != 0 or not addr:
        raise RuntimeError(f"no IP for {name}: {err}")
    return addr


def wait_banner(host, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, _, _ = sh([
            "docker", "exec", "msl-client", "python3", "-c",
            "import socket,sys\n"
            f"s=socket.create_connection(({host!r},25),5)\n"
            "b=s.recv(120); s.close(); sys.exit(0 if b.startswith(b'220') else 1)\n",
        ], timeout=15)
        if code == 0:
            return True
        time.sleep(1)
    return False


def boot(name):
    sh(["docker", "rm", "-f", name], timeout=30)
    sh([
        "docker", "run", "-d", "--name", name, "--network", NET,
        "--cpus", "0.35", "--memory", "256m",
        "--entrypoint", "sleep", "received-lab-opensmtpd:latest", "infinity",
    ], check=True)
    return ip_of(name)


def configure(name, relay_ip):
    conf = (
        f"listen on 0.0.0.0 port 25 hostname {name}.lab.test\n"
        f'action "next" relay host smtp://{relay_ip}:25\n'
        'match from any for any action "next"\n'
    ).encode()
    code, _, err = sh([
        "docker", "exec", "-i", name, "sh", "-c",
        "cat > /etc/smtpd.conf && chmod 644 /etc/smtpd.conf && smtpd -n -f /etc/smtpd.conf",
    ], input_bytes=conf, timeout=30)
    if code != 0:
        raise RuntimeError(err[-500:])
    sh(["docker", "exec", "-d", name, "sh", "-c", "smtpd -d -v -f /etc/smtpd.conf > /tmp/smtpd.log 2>&1"], check=True)
    if not wait_banner(name):
        raise RuntimeError(f"{name} did not show a banner")


def read_log(name):
    _, out, err = sh(["docker", "exec", name, "cat", "/tmp/smtpd.log"], timeout=20)
    return out or err


def classify_header(raw: bytes) -> dict:
    head = raw.split(b"\r\n\r\n", 1)[0]
    strict, obs, newest = [], [], None
    for line in head.split(b"\r\n"):
        if not line.lower().startswith(b"received"):
            continue
        rest = line[8:]
        if rest.startswith(b":"):
            strict.append(line.decode("latin1"))
            newest = line.decode("latin1")
        elif rest[:1] in (b" ", b"\t") and b":" in rest[:4]:
            obs.append(line.decode("latin1"))
    return {
        "strict": len(strict),
        "obs": len(obs),
        "newest_strict": newest,
        "first_strict": strict[0] if strict else None,
    }


def sample_message(name, dest: Path) -> dict | None:
    code, out, err = sh(["docker", "exec", name, "smtpctl", "show", "queue"], timeout=15)
    if code != 0 or not out.strip():
        return {"smtpctl": err[-200:] or "empty queue"}
    # Queue lines contain an evpid-like token. Keep the last token that looks like one.
    evpid = None
    for token in out.replace("|", " ").split():
        if len(token) >= 16 and all(c in "0123456789abcdef" for c in token.lower()):
            evpid = token
    if evpid is None:
        (dest / "queue.txt").write_text(out, encoding="utf-8")
        return {"queue_text": out[:400]}
    code, msg, err = sh(["docker", "exec", name, "smtpctl", "show", "message", evpid], timeout=15)
    blob = msg if code == 0 and msg else err
    path = dest / f"{evpid}.txt"
    path.write_text(blob, encoding="utf-8", errors="replace")
    info = classify_header(blob.encode("latin1", "replace"))
    info["evpid"] = evpid
    return info


def summarize(text: str) -> dict:
    accepts = text.count("Message accepted for delivery")
    idx = text.find("5.4.6")
    before = text[:idx].count("Message accepted for delivery") if idx >= 0 else accepts
    return {
        "accepted_for_delivery": accepts,
        "accepted_before_first_546": before,
        "loop_detected": idx >= 0 or "Loop detected" in text,
        "first_546": text[max(0, idx - 80):idx + 120].replace("\n", " ") if idx >= 0 else "",
    }


def one(label, received_line):
    names = ("msl-osloop-a", "msl-osloop-b")
    case = STAGE / label
    (case / "samples").mkdir(parents=True, exist_ok=True)
    samples = []
    sent = {}
    reason = "error"
    elapsed = 0.0
    try:
        boot(names[0])
        boot(names[1])
        configure(names[0], ip_of(names[1]))
        configure(names[1], ip_of(names[0]))
        raw = (
            f"X-Case-ID: {label}\r\n"
            f"{received_line}\r\n"
            "From: alice@lab.test\r\n"
            "To: bob@lab.test\r\n"
            "Subject: " + label + "\r\n"
            "Date: Thu, 1 Oct 2026 00:00:00 +0000\r\n"
            "Message-ID: <" + label + "@lab.test>\r\n"
            "\r\n"
            "loop\r\n"
        ).encode()
        (case / "input.eml").write_bytes(raw)
        code, out, err = sh([
            "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
            "--server", names[0], "--port", "25",
            "--input", f"/evidence/w1-20261001a/osmtpd-loop/{label}/input.eml",
            "--transcript", f"/evidence/w1-20261001a/osmtpd-loop/{label}/smtp.txt",
        ], timeout=40)
        sent = {}
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "raw": (out or err)[-400:]}
        log(f"{label} smtp accepted={sent.get('accepted')} reply={sent.get('reply')}")
        started = time.time()
        reason = "time-safety"
        while time.time() - started < SAFETY_SECONDS:
            text = read_log(names[0]) + "\n" + read_log(names[1])
            facts = summarize(text)
            snap = sample_message(names[0], case / "samples")
            samples.append({"t": round(time.time() - started, 1), **facts, "message": snap})
            if facts["loop_detected"]:
                reason = "loop-detected"
                break
            if facts["accepted_for_delivery"] >= ACCEPT_CAP:
                reason = "accept-cap"
                break
            time.sleep(1)
        elapsed = round(time.time() - started, 1)
    finally:
        sh(["docker", "stop", "-t", "2", *names], timeout=30)
        for name, side in zip(names, ("a", "b")):
            sh(["docker", "cp", f"{name}:/tmp/smtpd.log", str(case / f"{side}.log")], timeout=30)
        sh(["docker", "rm", "-f", *names], timeout=30)
    logs = ""
    for side in ("a", "b"):
        path = case / f"{side}.log"
        if path.exists():
            logs += path.read_text(encoding="utf-8", errors="replace")
    final = summarize(logs)
    final.update({
        "label": label,
        "seed": received_line,
        "stop_reason": reason,
        "seconds": elapsed,
        "safety_seconds": SAFETY_SECONDS,
        "accept_cap": ACCEPT_CAP,
        "smtp": sent,
        "samples": samples[-8:],
    })
    (case / "summary.json").write_text(json.dumps(final, indent=2) + "\n", encoding="utf-8")
    log(f"{label} stop={reason} accepts={final['accepted_for_delivery']} before546={final['accepted_before_first_546']} seconds={elapsed}")
    return final


def main():
    STAGE.mkdir(parents=True, exist_ok=True)
    code, _, _ = sh(["docker", "inspect", "-f", "{{.State.Running}}", "msl-client"], timeout=20)
    if code != 0:
        raise SystemExit("msl-client is not running")
    rows = [
        one(
            "loop-normal",
            "Received: from origin.example (origin.example [203.0.113.10]) by relay.example with ESMTP; Thu, 1 Oct 2026 00:00:00 +0000",
        ),
        one(
            "loop-obs",
            "Received : from origin.example (origin.example [203.0.113.10]) by relay.example; Thu, 1 Oct 2026 00:00:00 +0000",
        ),
    ]
    (STAGE / "summary.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# OpenSMTPD 同构环",
        "",
        "两台 OpenSMTPD 6.8.0p2 互相转发。停在第一次 `5.4.6`，或接受次数到达 160。180 秒只是安全上限。",
        "",
    ]
    for row in rows:
        lines.append(
            f"- {row['label']}: stop={row['stop_reason']} seconds={row['seconds']} "
            f"accepted={row['accepted_for_delivery']} before_first_546={row['accepted_before_first_546']}"
        )
        if row.get("first_546"):
            lines.append(f"  first 5.4.6: {row['first_546']}")
    lines.append("")
    (STAGE / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
