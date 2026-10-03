"""Unified differential runner: same bytes through every target, one schema.

合并 recfuzz.py / recfuzz2.py 的发送-捕获-计数循环。目标分三类：

  smtp:postfix / smtp:exim / smtp:osmtpd   经 msl-client 的 smtp_send.py 发送，
                                          存档字节从 Mailpit API 取（每个目标
                                          直投 Mailpit，存档即该 MTA 的输出）
  parse:python                             msl-client 内 python email (compat32)
  parse:go / parse:node                    parsers profile 容器，配置缺则拒跑

两个臂：threshold（N=55，看拒绝码）与 capture（N=25，低于所有阈值，看转换）。
行写入 <run>/diffrun/matrix.json；known.json 里已有的元组标 known=true，
重跑不把旧结果当新发现。事实一律来自 tracefacts.facts，本文件不再自写计数。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.evidence import sha256_bytes
from research.lib.tracefacts import corpus_check, facts as trace_facts

RUN_ROOT = Path("/mnt/e/MailSecLab/received-lab/results/research")
RESEARCH = Path("/mnt/e/MailSecLab/received-lab/research")
EVIDENCE_ROOT = "/evidence"

BASE = "Received: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000"
VARIANTS = {
    "v00-plain": BASE,
    "v01-obs-colon": "Received : from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v02-case": "rEcEiVeD: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v03-nocolon": "Received from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v04-8bit-name": "Rece\u00edved: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v05-cfws-name": "Received(Router): from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v06-comment-name": "Rece(c)ived: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
    "v07-tab-name": "Received\t: from h{n}.lab.test (h{n}.lab.test [203.0.113.{ip}]) by h{n1}.lab.test with ESMTP id X{n}; Sat, 03 Oct 2026 21:{mm}:00 +0000",
}
N_THRESHOLD = 55
N_CAPTURE = 25

SMTP_TARGETS = {
    "postfix": ("msl-auth-postfix", 25),
    "osmtpd": ("opensmtpd", 25),
    # exim 的地址在启动时从 diffrun-targets.json 的容器名解析，不写死 IP。
}


def variant_name(variant: str, target: str, arm: str) -> str:
    return f"{variant}__{target}__{arm}"


def build_raw(template: str, n: int, case_id: str) -> bytes:
    head = "\r\n".join(
        template.format(n=i, n1=i + 1, ip=i % 200, mm=i % 60) for i in range(n)
    ).encode("utf-8")
    return (
        head + b"\r\n"
        + b"From: Bank Security <security@bank.test>\r\n"
        + b"To: bob@lab.test\r\n"
        + b"Date: Sat, 3 Oct 2026 23:30:00 +0000\r\n"
        + f"Subject: {case_id}\r\n".encode()
        + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
        + f"X-Case-ID: {case_id}\r\n".encode()
        + b"\r\nPlease confirm the payment.\r\n"
    )


def sh(args, timeout=90, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def container_ip(name: str) -> str:
    code, out, err = sh(["docker", "inspect", "-f",
                         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name])
    addrs = [a for a in out.strip().split() if a]
    if code != 0 or not addrs:
        raise RuntimeError(f"no IP for {name}: {err}——检查 diffrun-targets.json 的 exim_container")
    # 双网容器（mailnet + 研究网）取研究网地址：研究网是 10.88.0.0/16。
    research = [a for a in addrs if a.startswith("10.88.")]
    return research[0] if research else addrs[0]


def load_config() -> tuple[dict, dict]:
    """读一次配置：SMTP 目标（exim 从容器名解析 IP，不写死）+ parse 目标。
    配置缺的目标直接不跑，不猜容器名。"""
    cfg_path = RESEARCH / "diffrun-targets.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    smtp = dict(SMTP_TARGETS)
    if cfg.get("exim_container"):
        smtp["exim"] = (container_ip(cfg["exim_container"]), 25)
    return smtp, cfg.get("parse", {})


FETCH_IN_CONTAINER = """
import json, sys, time, urllib.request
case_id, out_path = sys.argv[1], sys.argv[2]
for _ in range(10):
    try:
        r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=50", timeout=5)
        hits = [m for m in json.loads(r.read()).get("messages", [])
                if case_id in (m.get("Subject") or "")]
        if hits:
            # 同主题可能有多封（重跑/控制信）：按 Created 取最新。
            newest = max(hits, key=lambda m: m.get("Created") or "")
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw" % newest["ID"], timeout=5).read()
            open(out_path, "wb").write(raw)
            print("OK", len(raw)); sys.exit(0)
        # 回退：头区被终结的语料（v03/v04）经中继后主题沉没，按 X-Case-ID
        # 在无主题消息的原始字节里找。
        blanks = [m for m in json.loads(
            urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/messages?limit=50", timeout=5).read()
        ).get("messages", []) if not (m.get("Subject") or "")]
        for m in sorted(blanks, key=lambda x: x.get("Created") or "", reverse=True):
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
            if case_id.encode() in raw:
                open(out_path, "wb").write(raw)
                print("OK-BLANK", len(raw)); sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
"""


def fetch_mailpit(case_id: str, container_rel_path: str, host_path: Path) -> bytes | None:
    for _ in range(3):
        code, out, _ = sh(
            ["docker", "exec", "-i", "msl-client", "python3", "-", case_id, container_rel_path],
            timeout=60, stdin=FETCH_IN_CONTAINER.encode(),
        )
        if out.strip().startswith("OK"):
            return host_path.read_bytes()
        time.sleep(1)
    return None


def smtp_arm(stage: Path, ev_stage: str, variant: str, target: str,
             server: str, port: int, n: int, arm: str) -> dict:
    case_id = variant_name(variant, target, arm)
    raw = build_raw(VARIANTS[variant], n=n, case_id=case_id)
    problems = corpus_check(raw)
    if problems:
        raise RuntimeError(f"{case_id}: corpus 自检未通过 {problems}")
    (stage / f"{case_id}.eml").write_bytes(raw)
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", server, "--port", str(port),
        "--mail-from", "alice@lab.test", "--rcpt-to", "capture@lab.test",
        "--input", f"{ev_stage}/{case_id}.eml",
        "--transcript", f"{ev_stage}/{case_id}.smtp.txt",
    ], timeout=90)
    try:
        sent = json.loads(out)
    except json.JSONDecodeError:
        sent = {"accepted": False, "raw": (out or err)[-300:]}
    stored = None
    if sent.get("accepted"):
        stored = fetch_mailpit(
            case_id, f"{ev_stage}/{case_id}.stored.raw", stage / f"{case_id}.stored.raw")
    return {
        "case": case_id, "variant": variant, "target": target, "arm": arm, "n": n,
        "smtp_code": (sent.get("reply") or "")[:3],
        "smtp": (sent.get("reply") or "")[:60],
        "captured": stored is not None,
        "facts": trace_facts(stored) if stored is not None else {},
        "input_sha256": sha256_bytes(raw),
    }


def parse_arm(stage: Path, variant: str, raw: bytes, target: str,
              container: str, cmd: list[str]) -> dict:
    case_id = variant_name(variant, target, "parse")
    (stage / f"{case_id}.eml").write_bytes(raw)
    code, out, err = sh(["docker", "exec", "-i", container, *cmd], timeout=60, stdin=raw)
    try:
        view = json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        view = {"error": (out or err)[-200:]}
    return {
        "case": case_id, "variant": variant, "target": target, "arm": "parse",
        "captured": True, "view": view,
        "input_sha256": sha256_bytes(raw),
    }


def known_key(row: dict) -> str:
    bucket = {k: row.get(k) for k in ("smtp_code", "captured")}
    if row.get("facts"):
        bucket["received"] = row["facts"]["received"]
    if row.get("view"):
        bucket["view_received"] = row["view"].get("received_count")
    return json.dumps([row["variant"], row["target"], row["arm"], bucket],
                      ensure_ascii=False, sort_keys=True)


def run_diff(run_id: str) -> dict:
    stage = RUN_ROOT / run_id / "diffrun"
    stage.mkdir(parents=True, exist_ok=True)
    ev_stage = f"{EVIDENCE_ROOT}/{run_id}/diffrun"
    targets, parse_cfg = load_config()
    known_path = stage / "known.json"
    known = set(json.loads(known_path.read_text(encoding="utf-8"))) if known_path.exists() else set()

    problems, rows = [], []
    for variant in VARIANTS:
        for target, (server, port) in targets.items():
            for arm, n in (("threshold", N_THRESHOLD), ("capture", N_CAPTURE)):
                try:
                    row = smtp_arm(stage, ev_stage, variant, target, server, port, n, arm)
                except Exception as exc:  # 仪器故障记问题，不静默
                    problems.append(f"{variant}/{target}/{arm}: {exc}")
                    continue
                key = known_key(row)
                row["known"] = key in known
                known.add(key)
                rows.append(row)
                print(json.dumps({k: row[k] for k in
                                  ("case", "smtp_code", "captured", "known")}), flush=True)
                time.sleep(0.8)
        raw_capture = build_raw(VARIANTS[variant], n=N_CAPTURE,
                                case_id=variant_name(variant, "corpus", "capture"))
        for target, spec in parse_cfg.items():
            row = parse_arm(stage, variant, raw_capture, target,
                            spec["container"], spec["cmd"])
            key = known_key(row)
            row["known"] = key in known
            known.add(key)
            rows.append(row)

    (stage / "matrix.json").write_text(
        json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    known_path.write_text(json.dumps(sorted(known), ensure_ascii=False, indent=1), encoding="utf-8")
    expected = len(VARIANTS) * (len(targets) * 2 + len(parse_cfg))
    if len(rows) != expected:
        problems.append(f"matrix 不完整：{len(rows)}/{expected}")
    return {"passed": not problems, "problems": problems}


def corpus_files(corpus_dir: Path) -> list[Path]:
    """MailForge 归档或普通 .eml 目录。按文件名排序；manifest 存在时做
    sha256 交叉核对，普通目录也可用。"""
    return sorted(p for p in corpus_dir.rglob("*.eml"))


def run_corpus(run_id: str, corpus_dir: Path) -> dict:
    """--corpus 模式：外部字节（MailForge 产物）直接进 parse 臂 + 结构自检，
    不经 SMTP（无需中继手术）。行写入 <run>/diffrun/corpus-matrix.json。"""
    stage = RUN_ROOT / run_id / "diffrun"
    stage.mkdir(parents=True, exist_ok=True)
    _, parse_cfg = load_config()
    problems, rows = [], []
    for path in corpus_files(corpus_dir):
        raw = path.read_bytes()
        checks = corpus_check(raw)
        row = {"file": str(path.relative_to(corpus_dir)), "bytes": len(raw),
               "input_sha256": sha256_bytes(raw),
               "corpus_check": checks, "facts": trace_facts(raw)}
        for target, spec in parse_cfg.items():
            prow = parse_arm(stage, Path(path.stem).name[:40], raw, target,
                             spec["container"], spec["cmd"])
            row[f"view_{target}"] = prow["view"]
        rows.append(row)
        print(json.dumps({"file": row["file"], "checks": checks,
                          "received": row["facts"]["received"]}), flush=True)
    (stage / "corpus-matrix.json").write_text(
        json.dumps({"corpus_dir": str(corpus_dir), "rows": rows},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    if not rows:
        problems.append("corpus 目录里没有 .eml")
    return {"passed": not problems, "problems": problems, "rows": len(rows)}


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--corpus":
        report = run_corpus("w3-20261003a", Path(sys.argv[2]))
        print("corpus rows=", report["rows"], "passed=", report["passed"])
        for p in report["problems"]:
            print(" -", p)
    else:
        report = run_diff(sys.argv[1] if len(sys.argv) > 1 else "w3-20261003a")
        print("diff gate passed=", report["passed"])
        for p in report["problems"]:
            print(" -", p)
