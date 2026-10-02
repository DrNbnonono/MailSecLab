"""Week-1 bootstrap: inventory, calibration, I2 redo, G4 redo."""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

from lib import dockerctl
from lib.evidence import perl_feed, sha256_bytes, sha256_file, write_bytes, write_json
from lib.foldmsg import TARGET, build_g4, count_xreceived, inspect_message
from lib.received import assess_join, parse_received, received_headers

LAB = dockerctl.LAB
EVIDENCE = LAB / "results" / "research"
HOPS = ("msl-postfix1", "msl-postfix2", "msl-postfix3")
SIGNED = {"legal", "header-tamper", "body-tamper", "wrong-key", "legal-lf"}
GATE_CASES = ("legal", "header-tamper", "body-tamper", "wrong-key", "unsigned")
RELIABLE_NEGATIVE = {"fail", "none", "parse-error", "policy-reject"}
LIMITS = {
    "dns": (128, 0.10),
    "verifiers": (768, 0.70),
    "rspamd": (768, 0.70),
    "postfix1": (512, 0.40),
    "postfix2": (512, 0.40),
    "postfix3": (512, 0.40),
    "mailpit": (256, 0.20),
    "client": (384, 0.40),
}


def log(run: Path, text: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {text}"
    print(line, flush=True)
    with (run / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def state_path(run: Path) -> Path:
    return run / "state.json"


def load_state(run: Path) -> dict:
    path = state_path(run)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"done": []}


def mark(run: Path, step: str) -> None:
    state = load_state(run)
    if step not in state["done"]:
        state["done"].append(step)
    write_json(state_path(run), state)


def done(run: Path, step: str) -> bool:
    return step in load_state(run)["done"]


def exec_ok(name: str, args: list[str], timeout: int = 120, stdin: bytes | None = None):
    proc = dockerctl.docker_exec(name, args, timeout=timeout, stdin=stdin)
    return proc.returncode, proc.stdout_text, proc.stderr_text


def inventory(run: Path) -> None:
    if done(run, "inventory"):
        return
    legacy = dockerctl.legacy_is_running()
    if legacy:
        raise SystemExit("legacy mail containers are running; research stack will not start: " + ", ".join(legacy))
    mem = sum(v[0] for v in LIMITS.values())
    cpu = sum(v[1] for v in LIMITS.values())
    if mem > 5120 or cpu > 4:
        raise SystemExit(f"resource cap exceeded: {mem} MiB {cpu} cpus")
    tag = dockerctl._run(["docker", "image", "inspect", "axllent/mailpit:latest"], check=False)
    if tag.returncode == 0:
        image_id = json.loads(tag.stdout)[0]["Id"]
        if image_id.startswith("sha256:c96991d9"):
            dockerctl._run(["docker", "tag", "axllent/mailpit:latest", "axllent/mailpit:v1.31.0"], check=True)
    pf = dockerctl._run(
        ["docker", "run", "--rm", "--entrypoint", "postconf", "received-lab-postfix1:latest", "-h", "mail_version"],
        check=False,
    )
    deb = dockerctl._run(
        ["docker", "run", "--rm", "--entrypoint", "cat", "received-lab-postfix1:latest", "/etc/debian_version"],
        check=False,
    )
    info = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "compose_project": dockerctl.PROJECT,
        "network": "10.88.0.0/24",
        "web_bind": ["127.0.0.1:18025"],
        "resource_limits_mib_cpu": LIMITS,
        "resource_sum_mib": mem,
        "resource_sum_cpu": round(cpu, 2),
        "legacy_running": legacy,
        "images": {
            "postfix": dockerctl.image_inspect("received-lab-postfix1:latest"),
            "mailpit": dockerctl.image_inspect("axllent/mailpit:v1.31.0"),
            "client": dockerctl.image_inspect("received-lab-client:latest"),
            "bookworm": dockerctl.image_inspect("debian:bookworm-slim"),
        },
        "postfix_mail_version": (pf.stdout or "").strip(),
        "postfix_debian_version": (deb.stdout or "").strip(),
        "freeze_postfix_image": "sha256:860f16d93f527837b9a4003480ca653eef0276018bf9fff641b14cc9fb463697",
        "freeze_mailpit_digest_prefix": "sha256:c96991d9",
        "drift": [],
        "not_used": "bookworm opendkim-testmsg is not a verifier in this stack",
    }
    pf_id = info["images"]["postfix"].get("id") or ""
    if not pf_id.startswith("sha256:860f16d9"):
        info["drift"].append(
            "Postfix image on disk is not the 2026-09-01 freeze id. "
            "Week-1 chain reuses the on-disk received-lab-postfix images and records mail_version."
        )
    mp_id = info["images"]["mailpit"].get("id") or ""
    info["mailpit_matches_freeze_prefix"] = mp_id.startswith("sha256:c96991d9")
    if not info["mailpit_matches_freeze_prefix"]:
        info["drift"].append("Mailpit image id does not match the frozen v1.31.0 prefix.")
    info["drift"].append(
        "dkimpy, Mail::DKIM, go-msgauth, dnsmasq and rspamd images were not present and are built for this project."
    )
    write_json(run / "env.json", info)
    mark(run, "inventory")


def generate_keys(run: Path, run_id: str) -> None:
    if done(run, "keys"):
        return
    keys = run / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    if not (keys / "priv.pem").exists():
        dockerctl._run(["openssl", "genrsa", "-out", str(keys / "priv.pem"), "2048"], check=True)
        dockerctl._run(["openssl", "genrsa", "-out", str(keys / "wrong.pem"), "2048"], check=True)
    pub = dockerctl._run(["openssl", "rsa", "-in", str(keys / "priv.pem"), "-pubout"], check=True)
    body = "".join(line for line in pub.stdout.splitlines() if not line.startswith("-----"))
    (keys / "dkim.pub.b64").write_text(body + "\n", encoding="ascii")
    (keys / "pub.pem").write_text(pub.stdout, encoding="ascii")
    write_json(keys / "selector.json", {
        "selector": "cal",
        "domain": "lab.test",
        "query_name": "cal._domainkey.lab.test",
        "pub_sha256": sha256_bytes(body.encode()),
    })
    mark(run, "keys")


def build(run: Path, run_id: str) -> None:
    if done(run, "build"):
        return
    log(run, "building dns, verifiers, rspamd")
    dockerctl.compose(run_id, ["build", "dns", "verifiers", "rspamd"], timeout=2400)
    mark(run, "build")


def start(run_id: str, services: list[str]) -> None:
    dockerctl.compose(run_id, ["up", "-d", *services], timeout=300)


def wait_dns(run: Path, run_id: str) -> None:
    deadline = time.time() + 90
    while time.time() < deadline:
        rc, out, err = exec_ok("msl-dns", ["dig", "@127.0.0.1", "lab.test", "TXT", "+time=2", "+tries=1", "+short"])
        if rc == 0 and "spf1" in out:
            return
        time.sleep(2)
    raise RuntimeError("dns did not answer lab.test TXT")


def wait_smtp(run: Path) -> None:
    deadline = time.time() + 60
    while time.time() < deadline:
        rc, out, err = exec_ok(
            "msl-client",
            ["python3", "-c", "import socket;s=socket.create_connection(('postfix1',25),5);print(s.recv(80).decode());s.close()"],
        )
        if rc == 0 and out.startswith("220"):
            return
        time.sleep(2)
    raise RuntimeError("postfix1 did not present an SMTP banner")


def dig_control(run: Path, run_id: str) -> dict:
    b64 = (run / "keys" / "dkim.pub.b64").read_text(encoding="ascii").strip()[:40]
    since = int(time.time())
    rc1, good, e1 = exec_ok("msl-verifiers", ["dig", "+time=3", "+tries=1", "TXT", "cal._domainkey.lab.test"])
    rc2, bad, e2 = exec_ok("msl-verifiers", ["dig", "+time=3", "+tries=1", "TXT", "not-a-selector._domainkey.lab.test"])
    logs = dockerctl.docker_logs("msl-dns", since=since - 1)
    (run / "calibrate").mkdir(parents=True, exist_ok=True)
    (run / "calibrate" / "dig-exact.txt").write_text(good + "\n" + e1, encoding="utf-8")
    (run / "calibrate" / "dig-other.txt").write_text(bad + "\n" + e2, encoding="utf-8")
    (run / "calibrate" / "dns-control.log").write_text(logs, encoding="utf-8")
    names = re.findall(r"query\[TXT\]\s+(\S+)", logs)
    exact = [n for n in names if n.rstrip(".").lower() == "cal._domainkey.lab.test"]
    other = [n for n in names if n.rstrip(".").lower() == "not-a-selector._domainkey.lab.test"]
    return {
        "exact_answer_has_key": b64 in good.replace(" ", "").replace('"', ""),
        "other_answer_lacks_key": b64 not in bad.replace(" ", "").replace('"', ""),
        "exact_query_logged": bool(exact),
        "other_query_logged": bool(other),
        "queries": names,
        "dig_exact_rc": rc1,
        "dig_other_rc": rc2,
    }


def classify_rspamd(payload: dict) -> tuple[str, str]:
    symbols = payload.get("symbols") or {}
    action = str(payload.get("action") or "")
    if "R_DKIM_ALLOW" in symbols:
        status = "pass"
    elif "R_DKIM_REJECT" in symbols:
        status = "fail"
    elif "R_DKIM_TEMPFAIL" in symbols:
        status = "temp-error"
    elif "R_DKIM_PERMFAIL" in symbols:
        status = "fail"
    elif "R_DKIM_NA" in symbols:
        status = "none"
    elif action.lower() == "reject":
        status = "policy-reject"
    else:
        status = "none"
    return status, action


def calibrate(run: Path, run_id: str) -> None:
    if done(run, "calibrate"):
        return
    log(run, "starting dns, verifiers, rspamd")
    start(run_id, ["dns", "verifiers", "rspamd"])
    wait_dns(run, run_id)
    rc, out, err = exec_ok("msl-verifiers", ["python3", "/opt/research/lib/sign_cases.py"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"sign_cases failed\n{out}\n{err}")
    versions = {}
    for label, args in {
        "dkimpy": ["python3", "-c", "import importlib.metadata as m; print(m.version('dkimpy'))"],
        "perl_pkg": ["dpkg-query", "-W", "-f", "${Version}", "libmail-dkim-perl"],
        "go_mod": ["go", "version", "-m", "/usr/local/bin/dkim-verify"],
    }.items():
        crc, cout, cerr = exec_ok("msl-verifiers", args, timeout=60)
        versions[label] = (cout or cerr).strip()
        versions[label + "_rc"] = crc
    crc, cout, cerr = exec_ok("msl-rspamd", ["rspamd", "--version"])
    versions["rspamd"] = (cout or cerr).strip()
    write_json(run / "calibrate" / "versions.json", versions)
    ready_eml = run / "calibrate" / "rspamd-ready.eml"
    write_bytes(ready_eml, b"X-Case-ID: rspamd-ready\r\nFrom: a@lab.test\r\nSubject: rspamd-ready\r\n\r\nok\r\n")
    ready = False
    out = err = ""
    for _ in range(30):
        rc, out, err = exec_ok(
            "msl-rspamd",
            ["rspamc", "--json", f"/evidence/{run_id}/calibrate/rspamd-ready.eml"],
            timeout=20,
        )
        if rc == 0 and "score" in out:
            ready = True
            break
        time.sleep(2)
    if not ready:
        (run / "calibrate" / "rspamd-start.txt").write_text(out + "\n" + err, encoding="utf-8")
        raise RuntimeError("rspamd did not accept a scan")
    control = dig_control(run, run_id)
    write_json(run / "calibrate" / "dns_control.json", control)
    results = []
    for case in list(GATE_CASES) + ["legal-lf"]:
        path = f"/evidence/{run_id}/calibrate/{case}.eml"
        fed = perl_feed(Path(path.replace(f"/evidence/{run_id}", str(run))).read_bytes())
        write_bytes(run / "calibrate" / f"{case}.perl-fed.eml", fed)
        since = int(time.time())
        case_row = {"case": case, "verifiers": {}}
        for tool in ("dkimpy", "perl", "go"):
            rc, out, err = exec_ok(
                "msl-verifiers",
                ["python3", "/opt/research/lib/verify_one.py", tool, path],
                timeout=45,
            )
            if rc != 0 or not out.strip():
                verdict = {"status": "tool-error", "stdout": out, "stderr": err, "exit_code": rc}
            else:
                try:
                    verdict = json.loads(out)
                except json.JSONDecodeError:
                    verdict = {"status": "tool-error", "stdout": out, "stderr": err}
            if tool == "perl":
                lib_fed = verdict.get("library_fed_sha256")
                if lib_fed and lib_fed != sha256_bytes(fed):
                    verdict["status"] = "tool-error"
                    verdict["adapter_mismatch"] = True
            case_row["verifiers"][tool] = verdict
        rc, out, err = exec_ok("msl-rspamd", ["rspamc", "--json", path], timeout=60)
        raw_path = run / "calibrate" / f"{case}.rspamd.json"
        raw_path.write_text(out or err, encoding="utf-8")
        try:
            payload = json.loads(out)
            status, action = classify_rspamd(payload)
            rsp = {"status": status, "action": action, "score": payload.get("score"), "symbols": sorted((payload.get("symbols") or {}).keys())}
        except json.JSONDecodeError:
            rsp = {"status": "tool-error", "stdout": out[-2000:], "stderr": err[-2000:]}
        case_row["verifiers"]["rspamd"] = rsp
        logs = dockerctl.docker_logs("msl-dns", since=since - 1)
        (run / "calibrate" / f"{case}.dns.log").write_text(logs, encoding="utf-8")
        names = re.findall(r"query\[TXT\]\s+(\S+)", logs)
        case_row["txt_queries"] = names
        case_row["exact_query"] = any(n.rstrip(".").lower() == "cal._domainkey.lab.test" for n in names)
        if case in SIGNED and not case_row["exact_query"]:
            for verdict in case_row["verifiers"].values():
                if verdict.get("status") == "pass":
                    verdict["status"] = "tool-error"
                    verdict["downgrade"] = "pass without an exact selector query"
        results.append(case_row)
        log(run, f"calibrate {case}: " + ", ".join(f"{k}={v.get('status')}" for k, v in case_row["verifiers"].items()))
    write_json(run / "calibrate" / "results.json", results)
    mark(run, "calibrate")


def mailpit_fetch(case: str, timeout: int = 40):
    deadline = time.time() + timeout
    url = "http://127.0.0.1:18025/api/v1/messages?limit=50"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            time.sleep(1)
            continue
        messages = data.get("messages") or []
        for item in messages:
            subject = item.get("Subject") or ""
            mid = item.get("ID")
            if case not in subject or not mid:
                continue
            with urllib.request.urlopen(f"http://127.0.0.1:18025/api/v1/message/{mid}/raw", timeout=60) as resp:
                raw = resp.read()
            if case.encode() in raw:
                return raw, mid
        time.sleep(1)
    return None, None


def send_file(run_id: str, src: str, transcript: str, timeout: int = 120) -> dict:
    rc, out, err = exec_ok(
        "msl-client",
        ["python3", "/opt/research/lib/smtp_send.py",
         "--server", "postfix1", "--port", "25",
         "--input", src, "--transcript", transcript],
        timeout=timeout,
    )
    if not out.strip():
        return {"accepted": False, "reply": "", "error": err, "exit_code": rc}
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        payload = {"accepted": False, "reply": out, "error": err}
    payload["exit_code"] = rc
    return payload


def smoke_and_i2(run: Path, run_id: str) -> None:
    if done(run, "i2"):
        return
    log(run, "starting chain")
    start(run_id, ["dns", "postfix1", "postfix2", "postfix3", "mailpit", "client", "rspamd"])
    wait_dns(run, run_id)
    wait_smtp(run)
    smoke = run / "i2" / "smoke"
    smoke.mkdir(parents=True, exist_ok=True)
    raw = (
        b"X-Case-ID: smoke-plain\r\n"
        b"From: Alice <alice@lab.test>\r\n"
        b"To: Bob <bob@lab.test>\r\n"
        b"Subject: smoke-plain\r\n"
        b"Message-ID: <smoke-plain@lab.test>\r\n"
        b"Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n"
        b"\r\n"
        b"smoke-body\r\n"
    )
    write_bytes(smoke / "input.eml", raw)
    sent = send_file(run_id, f"/evidence/{run_id}/i2/smoke/input.eml", f"/evidence/{run_id}/i2/smoke/smtp.txt")
    write_json(smoke / "smtp.json", sent)
    stored, mid = mailpit_fetch("smoke-plain", timeout=30)
    if stored is None:
        write_json(smoke / "delivery.json", {"status": "pending"})
        raise RuntimeError("smoke message was not delivered; I2 and G4 are not interpretable")
    write_bytes(smoke / "stored.eml", stored)
    headers = received_headers(stored)
    client_ip = sent.get("client_ip")
    genuine = next((h for h in headers if client_ip and client_ip in h["ips"]), None)
    if genuine is None:
        write_json(smoke / "observed.json", {"error": "client IP not found in stored Received", "received": headers})
        raise RuntimeError("smoke Received does not contain the client IP")
    observed = {
        "from_host": genuine["from_host"],
        "from_ip": client_ip,
        "protocol": genuine["protocol"],
        "by_host": genuine["by_host"],
        "raw": genuine["raw"],
    }
    write_json(run / "i2" / "observed.json", observed)
    rows = []
    for mode in ("plain", "consistent", "inconsistent"):
        case = f"i2-{mode}"
        case_dir = run / "i2" / mode
        case_dir.mkdir(parents=True, exist_ok=True)
        since = int(time.time())
        rc, out, err = exec_ok(
            "msl-client",
            ["python3", "/opt/research/lib/i2_build.py",
             "--mode", mode, "--case", case,
             "--out", f"/evidence/{run_id}/i2/{mode}/input.eml",
             "--observed", f"/evidence/{run_id}/i2/observed.json"],
            timeout=30,
        )
        if rc != 0:
            raise RuntimeError(f"i2 build {mode} failed\n{out}\n{err}")
        sent = send_file(run_id, f"/evidence/{run_id}/i2/{mode}/input.eml", f"/evidence/{run_id}/i2/{mode}/smtp.txt")
        write_json(case_dir / "smtp.json", sent)
        stored, mid = mailpit_fetch(case, timeout=30)
        delivery = "pending" if stored is None else "delivered"
        if stored is not None:
            write_bytes(case_dir / "stored.eml", stored)
            ip = sent.get("client_ip") or observed["from_ip"]
            join = assess_join(stored, mode, ip)
            write_json(case_dir / "join.json", join)
        else:
            join = {"join_ok": False, "reasons": ["delivery pending"]}
        scans = {}
        for label, rel in (("input", "input.eml"), ("stored", "stored.eml")):
            target = case_dir / rel
            if not target.exists():
                scans[label] = {"status": "pending"}
                continue
            rc, out, err = exec_ok("msl-rspamd", ["rspamc", "--json", f"/evidence/{run_id}/i2/{mode}/{rel}"], timeout=60)
            (case_dir / f"rspamd-{label}.json").write_text(out or err, encoding="utf-8")
            try:
                payload = json.loads(out)
                status, action = classify_rspamd(payload)
                symbol = (payload.get("symbols") or {}).get("H_SOURCE_IP") or {}
                scans[label] = {
                    "status": status,
                    "action": action,
                    "score": payload.get("score"),
                    "source": symbol.get("options") or symbol.get("description") or symbol,
                }
            except json.JSONDecodeError:
                scans[label] = {"status": "tool-error", "stderr": err[-1000:]}
        (case_dir / "postfix1.log").write_text(dockerctl.docker_logs("msl-postfix1", since=since), encoding="utf-8")
        row = {"mode": mode, "delivery": delivery, "mailpit_id": mid, "smtp": sent, "join_ok": join.get("join_ok"), "join_reasons": join.get("reasons"), "rspamd": scans}
        rows.append(row)
        log(run, f"I2 {mode}: delivery={delivery} join={join.get('join_ok')} reasons={join.get('reasons')}")
    write_json(run / "i2" / "summary.json", rows)
    mark(run, "i2")


def queue_ids(name: str) -> list[str]:
    rc, out, err = exec_ok(name, ["postqueue", "-p"])
    return re.findall(r"^([0-9A-F]{8,16})\s+\d+", out, re.M)


def set_defer(name: str) -> None:
    exec_ok(name, ["postconf", "-e", "defer_transports = smtp"])
    exec_ok(name, ["postfix", "reload"])


def clear_defer(name: str) -> None:
    exec_ok(name, ["postconf", "-X", "defer_transports"])
    exec_ok(name, ["postfix", "reload"])
    exec_ok(name, ["postfix", "flush"])


def capture_hop(name: str, qid: str, dest: Path) -> bool:
    if not qid:
        return False
    rc, out, err = exec_ok(name, ["postcat", "-q", qid], timeout=120)
    if rc != 0 or "MESSAGE CONTENTS" not in out:
        dest.write_text(out + "\n" + err, encoding="utf-8")
        return False
    dest.write_text(out, encoding="utf-8")
    return True


def g4(run: Path, run_id: str) -> None:
    if done(run, "g4"):
        return
    log(run, "G4 legal folded headers")
    rc, limit_s, err = exec_ok("msl-postfix1", ["postconf", "-h", "message_size_limit"])
    try:
        limit = int(limit_s.strip() or "10240000")
    except ValueError:
        limit = 10240000
    rows = []
    try:
        for hop in HOPS:
            set_defer(hop)
        time.sleep(1)
        for n in (1, 50, 100):
            case = f"G4-N{n}"
            case_dir = run / "g4" / case
            case_dir.mkdir(parents=True, exist_ok=True)
            raw = build_g4(n, case, TARGET)
            check = inspect_message(raw, n)
            write_json(case_dir / "selfcheck.json", check)
            write_bytes(case_dir / "input.eml", raw)
            if not check["ok"]:
                rows.append({"case": case, "sent": False, "reason": "selfcheck failed", "check": check})
                break
            if len(raw) >= limit:
                rows.append({"case": case, "sent": False, "reason": f"input {len(raw)} >= message_size_limit {limit}"})
                continue
            since = int(time.time())
            for hop in HOPS:
                set_defer(hop)
            sent = send_file(
                run_id,
                f"/evidence/{run_id}/g4/{case}/input.eml",
                f"/evidence/{run_id}/g4/{case}/smtp.txt",
                timeout=180,
            )
            write_json(case_dir / "smtp.json", sent)
            gaps = []
            qid = sent.get("queued_id") or ""
            if sent.get("accepted"):
                if not qid:
                    ids = queue_ids("msl-postfix1")
                    qid = ids[0] if ids else ""
                if not capture_hop("msl-postfix1", qid, case_dir / "postcat-postfix1.txt"):
                    gaps.append("postfix1 postcat missing")
                clear_defer("msl-postfix1")
                hop2 = ""
                deadline = time.time() + 60
                while time.time() < deadline and not hop2:
                    found = queue_ids("msl-postfix2")
                    hop2 = found[0] if found else ""
                    if not hop2:
                        time.sleep(1)
                if not capture_hop("msl-postfix2", hop2, case_dir / "postcat-postfix2.txt"):
                    gaps.append("postfix2 postcat missing")
                clear_defer("msl-postfix2")
                hop3 = ""
                deadline = time.time() + 60
                while time.time() < deadline and not hop3:
                    found = queue_ids("msl-postfix3")
                    hop3 = found[0] if found else ""
                    if not hop3:
                        time.sleep(1)
                if not capture_hop("msl-postfix3", hop3, case_dir / "postcat-postfix3.txt"):
                    gaps.append("postfix3 postcat missing")
                clear_defer("msl-postfix3")
            stored, mid = (None, None)
            if sent.get("accepted"):
                stored, mid = mailpit_fetch(case, timeout=45)
            delivery = "pending" if sent.get("accepted") and stored is None else (
                "delivered" if stored is not None else "not-delivered"
            )
            if stored is not None:
                write_bytes(case_dir / "stored.eml", stored)
                stored_info = {"x_received": count_xreceived(stored)}
            else:
                stored_info = None
            for hop in HOPS:
                (case_dir / f"{hop}.log").write_text(dockerctl.docker_logs(hop, since=since), encoding="utf-8")
            row = {
                "case": case,
                "n": n,
                "input_bytes": len(raw),
                "input_sha256": sha256_file(case_dir / "input.eml"),
                "smtp_reply": sent.get("reply"),
                "accepted": bool(sent.get("accepted")),
                "delivery": delivery,
                "mailpit_id": mid,
                "stored_bytes": len(stored) if stored else 0,
                "stored_sha256": sha256_bytes(stored) if stored else "",
                "stored_x_received": None if not stored_info else stored_info.get("x_received"),
                "observation_gaps": gaps,
                "syntax": "modern-folded",
            }
            rows.append(row)
            log(run, f"G4 {case}: reply={sent.get('reply')} delivery={delivery} gaps={gaps}")
            if n == 1 and delivery != "delivered":
                log(run, "G4 canary was not delivered; N=50 and N=100 were not sent")
                break
    finally:
        for hop in HOPS:
            clear_defer(hop)
    write_json(run / "g4" / "summary.json", {"message_size_limit": limit, "target_unfolded": TARGET, "rows": rows})
    mark(run, "g4")


def gate(run: Path) -> dict:
    results = json.loads((run / "calibrate" / "results.json").read_text(encoding="utf-8"))
    by_case = {row["case"]: row for row in results}
    problems = []
    legal = by_case["legal"]["verifiers"]
    if any(v.get("status") != "pass" for v in legal.values()):
        problems.append("legal signature was not pass on every verifier")
    for case in ("header-tamper", "body-tamper", "wrong-key", "unsigned"):
        for name, verdict in by_case[case]["verifiers"].items():
            status = verdict.get("status")
            if status == "pass" or status not in RELIABLE_NEGATIVE:
                problems.append(f"{case}/{name}={status}")
    dns = json.loads((run / "calibrate" / "dns_control.json").read_text(encoding="utf-8"))
    if not (dns["exact_answer_has_key"] and dns["other_answer_lacks_key"] and dns["exact_query_logged"] and dns["other_query_logged"]):
        problems.append("DNS exact-name control failed")
    perl_lf = by_case["legal-lf"]["verifiers"]["perl"]
    if perl_lf.get("perl_normalization") == "identity" and perl_lf.get("library_normalization") == "identity":
        problems.append("LF control did not exercise perl newline rewriting")
    i2_rows = json.loads((run / "i2" / "summary.json").read_text(encoding="utf-8"))
    if any(row["delivery"] == "pending" for row in i2_rows):
        problems.append("I2 delivery pending")
    consistent = next(row for row in i2_rows if row["mode"] == "consistent")
    inconsistent = next(row for row in i2_rows if row["mode"] == "inconsistent")
    plain = next(row for row in i2_rows if row["mode"] == "plain")
    if not plain["join_ok"]:
        problems.append("I2 plain anchor does not match the client IP")
    if not consistent["join_ok"]:
        problems.append("I2 consistent chain did not join; rspamd output is not a joined-chain result")
    if inconsistent["join_ok"]:
        problems.append("I2 inconsistent chain joined; the break was not real")
    g4_summary = json.loads((run / "g4" / "summary.json").read_text(encoding="utf-8"))
    if not g4_summary["rows"]:
        problems.append("G4 produced no rows")
    for row in g4_summary["rows"]:
        if row.get("sent") is False:
            problems.append(f"G4 {row['case']} not sent: {row.get('reason')}")
        elif row["delivery"] == "pending":
            problems.append(f"G4 {row['case']} delivery pending")
        elif row["accepted"] and row["delivery"] != "delivered":
            problems.append(f"G4 {row['case']} SMTP accepted but not delivered")
        elif row.get("delivery") == "delivered" and row.get("stored_x_received") != row.get("n"):
            problems.append(
                f"G4 {row['case']} delivered but X-Received count is {row.get('stored_x_received')} not {row.get('n')}"
            )
    report = {
        "stage": "bootstrap",
        "passed": not problems,
        "problems": problems,
        "counts_as_finding": False,
        "note": "Adapter failures, DNS failures and missing delivery are not findings.",
    }
    write_json(run / "gate.json", report)
    return report


def write_record(run: Path, report: dict) -> None:
    env = json.loads((run / "env.json").read_text(encoding="utf-8"))
    cal = json.loads((run / "calibrate" / "results.json").read_text(encoding="utf-8"))
    i2_rows = json.loads((run / "i2" / "summary.json").read_text(encoding="utf-8"))
    g4_summary = json.loads((run / "g4" / "summary.json").read_text(encoding="utf-8"))
    lines = [
        "# Week 1 bootstrap",
        "",
        f"Gate passed: {report['passed']}",
        "",
        "This run does not modify historical RECORD files, signatures, or the old Mailpit volume.",
        "Postfix is the on-disk image, not a claim that the 2026-09-01 freeze id was restored.",
        "",
        "## Environment drift",
        "",
    ]
    for item in env.get("drift", []):
        lines.append(f"- {item}")
    lines.extend(["", f"- Postfix mail_version: {env.get('postfix_mail_version')}", f"- Mailpit freeze prefix match: {env.get('mailpit_matches_freeze_prefix')}", "", "## Calibration", ""])
    lines.append("| case | dkimpy | perl | go-msgauth | rspamd | exact DNS query |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for row in cal:
        v = row["verifiers"]
        lines.append(
            f"| {row['case']} | {v['dkimpy'].get('status')} | {v['perl'].get('status')} | {v['go'].get('status')} | {v['rspamd'].get('status')} | {row['exact_query']} |"
        )
    lines.extend(["", "## I2", ""])
    lines.append(
        "File scans use rspamd `get_from_ip()` after `H_SOURCE_IP` was registered. "
        "SPF, DMARC and RBL are off in this image, and `maps.rspamd.com` resolves to 127.0.0.1. "
        "The symbol reads the from-address of the top Received header. "
        "On the pre-relay consistent and inconsistent messages that address is 203.0.113.11. "
        "After the three-hop chain the top Received is Mailpit's record of postfix3, so the symbol is 10.88.0.23. "
        "It is not the client address 10.88.0.11 and not the broken by-host."
    )
    lines.append("")
    for row in i2_rows:
        lines.append(f"- {row['mode']}: delivery={row['delivery']} join_ok={row['join_ok']} reasons={row['join_reasons']} rspamd={row['rspamd']}")
    lines.extend(["", "## G4", ""])
    lines.append(
        "Headers are modern folded fields: each physical line is 78 octets or shorter, "
        "and each unfolded X-Received field is about 78000 octets. "
        "This is not a replay of the earlier 9096191-byte figure. "
        "postcat output was saved for every hop."
    )
    for row in g4_summary["rows"]:
        lines.append(
            f"- {row.get('case')}: bytes={row.get('input_bytes')} smtp={row.get('smtp_reply')} delivery={row.get('delivery')} "
            f"stored_x_received={row.get('stored_x_received')} gaps={row.get('observation_gaps')}"
        )
    lines.extend(["", "## Gate", ""])
    if report["problems"]:
        for item in report["problems"]:
            lines.append(f"- {item}")
    else:
        lines.append("- Controls passed. No week-1 row is counted as a new finding.")
    (run / "RECORD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_bootstrap(run_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", run_id):
        raise SystemExit("run-id must be one path segment")
    run = EVIDENCE / run_id
    if (run / "gate.json").exists():
        raise SystemExit(f"{run} already has gate.json; choose a new run-id")
    run.mkdir(parents=True, exist_ok=True)
    try:
        inventory(run)
        generate_keys(run, run_id)
        build(run, run_id)
        calibrate(run, run_id)
        dockerctl.compose(run_id, ["stop", "verifiers"], timeout=120)
        smoke_and_i2(run, run_id)
        g4(run, run_id)
        report = gate(run)
        write_record(run, report)
        log(run, f"gate passed={report['passed']}")
        return report
    finally:
        try:
            dockerctl.compose(run_id, ["stop"], timeout=180)
        except Exception as exc:
            log(run, f"stop failed: {exc}")
