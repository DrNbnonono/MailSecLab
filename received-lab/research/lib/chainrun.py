"""chainrun: 链引擎——同一份种子字节经过有序异构 MTA 序列，逐终点收集判决向量。

remain.py 的 ad-hoc 容器模式泛化（w1 先例）+ diffrun 的事实/去重惯例 +
verdicts 的判决向量层。三层职责：

  序列执行    每序列起临时容器 msl-cr-<seq>-<pos>-<kind>，逐种子注入第一跳，
              末跳 relay 到终点。终点两臂：capture=msl-mailpit:1025（字节 +
              文件级四验证器）/ exec=msl-auth-postfix:25（milter AR + IMAP
              ENVELOPE + Dovecot 原文）。
  单跳前缀臂  对每条 (A,B) 序列同时跑 (A) 单跳——组合效应的分离基线。
              假设：A 的变换与其 relay 目标无关（变换发生在 A 的接受期），
              由 v00 控制信核验。
  norelay 臂  种子原始字节的文件级判决（对照基线，不起容器）。

Gap 1 协调（计划首部规则）：run_chain 默认检测到 Gap 1 近期活动即拒绝执行，
--gap1-clear 显式放行。本引擎不修改任何共享配置——一切「手术」都在自己的
临时容器内（这正是选 ad-hoc 容器而非 SURGERY 重放的原因）。

已知局限（诚实记录）：
  - ad-hoc exim（received-lab-exim:latest, /etc/exim/exim.conf）与 w3 diffrun
    用的 `exim` 容器（v3 镜像, /etc/exim4/exim4.conf）是两套配置布局；v01
    控制信必须核对两者行为一致，不一致先疑仪器。
  - Message-ID 非本引擎派生的种子（w1-from-above-mutant），rspamd milter 判决
    无法按 case-id 区分臂，记 not-collected。
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib import verdicts
from research.lib.chainseeds import SEEDS, Seed, build_control
from research.lib.evidence import sha256_bytes
from research.lib.tracefacts import corpus_check, facts as trace_facts

RUN_ROOT = Path("/mnt/e/MailSecLab/received-lab/results/research")
RESEARCH = Path("/mnt/e/MailSecLab/received-lab/research")
EVIDENCE_ROOT = "/evidence"
NET = "mailseclab-research-net"

IMAGES = {
    "pf": "received-lab-postfix1:latest",
    "ex": "received-lab-exim:latest",
    "os": "received-lab-opensmtpd:latest",
}
SINGLE_SEQUENCES = {"pf": ("pf",), "ex": ("ex",), "os": ("os",)}
ARM_ENDPOINTS = {"capture": ("msl-mailpit", 1025), "exec": ("msl-auth-postfix", 25)}
SEND_INTERVAL = 0.8

SEQUENCES_V0 = {
    "pf-ex": ("pf", "ex"), "pf-os": ("pf", "os"),
    "ex-pf": ("ex", "pf"), "ex-os": ("ex", "os"),
    "os-pf": ("os", "pf"), "os-ex": ("os", "ex"),
    "pf-pf": ("pf", "pf"), "ex-ex": ("ex", "ex"), "os-os": ("os", "os"),
}

# 计数组合探针（F3 已闭合的阈值背景下的组合轴，非重扫）：
#   v00/49  单跳 pf 投递（49+1=50≤50），pf-pf 在第二跳 50+1>50 拒——纯组合效应锚
#   v00/55  w3 锚：单跳 pf 554 / ex 退信 / os 投递
#   v01/29  obs 计数集合并集：os-ex（os 不计 obs，ex 计）vs pf-os（pf 先规范化）路径分岔
#   v01/55  w3 锚的 obs 版
THRESHOLD_PROBES = [("v00-plain", 49), ("v00-plain", 55),
                    ("v01-obs-colon", 29), ("v01-obs-colon", 55)]

# facts 的 relay 归因标记：ad-hoc OpenSMTPD 6.8 与 Mailpit 的 Received 行
# 无 by 子句，msl-cr- 出现在 reverse-DNS 括注里（如
# "from e55e50b6bea9 (msl-cr-os-os-1-os.mailseclab-research-net [10.88.0.8])"），
# 故用裸 msl-cr- 前缀；hop1 的行只提 msl-client（不计入）——zone_total 才是
# 控制信用的稳健度量，relay_added 只是辅助归因。
CHAIN_MARKERS = (b"msl-cr-", b"by msl-auth-postfix", b"by msl-mailpit",
                 b"by exim", b"by opensmtpd", b"by msl-postfix")

_REQUIRED_CONTAINERS = ("msl-client", "msl-mailpit", "msl-verifiers",
                        "msl-rspamd", "msl-auth-postfix", "msl-dovecot")


class ChainrunError(RuntimeError):
    pass


def case_id(seed: str, seq_name: str, arm: str) -> str:
    return f"{seed}__{seq_name}__{arm}"


def build_hop_plan(seq_kinds: tuple[str, ...], endpoint_host: str,
                   endpoint_port: int, seq_name: str) -> list[dict]:
    """编排计划：倒序启动（后跳先起，前跳才能解析它的地址）。"""
    plan = []
    for pos, kind in enumerate(seq_kinds, 1):
        if pos == len(seq_kinds):
            nxt, port = endpoint_host, endpoint_port
        else:
            nxt, port = f"msl-cr-{seq_name}-{pos + 1}-{seq_kinds[pos]}", 25
        plan.append({"kind": kind, "name": f"msl-cr-{seq_name}-{pos}-{kind}",
                     "next_host": nxt, "next_port": port})
    return plan


def check_seed_corpus(seed: Seed, raw: bytes) -> None:
    problems = corpus_check(raw)
    unadmitted = [p for p in problems
                  if not any(pat in p for pat in seed.admits_check)]
    if unadmitted:
        raise ChainrunError(f"种子 {seed.name} 语料自检未承认问题: {unadmitted}")


def expected_relay_delta(n_hops: int, arm: str) -> int:
    """v00 控制信过链后的 Received 总数增量。

    capture 臂 = 跳数 + 1：Mailpit 在 SMTP 收件时自盖一条 Received
    （证据：w3 sigprobe2 中 s0 三条签名经单跳后 strict=5 而非 4；
    本 run os-os 控制信字节——顶部 from 191e7f9af35f 行即 Mailpit 所加）。
    exec 臂 = 跳数 + 2：msl-auth-postfix 加一条 + Dovecot LMTP 再加一条
    （证据：w2 repair 直投存档，种子 0 预置 → 2 条：
    from client.lab.test + from auth-postfix.lab.test）。
    """
    return n_hops + (2 if arm == "exec" else 1)


def known_key(row: dict) -> str:
    bucket = {k: row.get(k) for k in ("smtp_code", "delivered")}
    if row.get("facts"):
        bucket["received"] = row["facts"].get("received")
    dkim = (row.get("verdicts") or {}).get("dkim")
    if dkim:
        bucket["dkim"] = dkim
    return json.dumps([row.get("seed"), row.get("sequence"), row.get("arm"), bucket],
                      ensure_ascii=False, sort_keys=True)


def message_id_from_raw(raw: bytes) -> str | None:
    m = re.search(rb"Message-ID:\s*<([^>]+)>", raw, re.IGNORECASE)
    return m.group(1).decode("utf-8", "replace") if m else None


# ---------------------------------------------------------------- docker 基元（remain.py 模式）

def sh(args, timeout=90, check=False, stdin=None):
    proc = subprocess_run(args, timeout, stdin)
    if check and proc.returncode != 0:
        raise ChainrunError(args[0] + " failed\n" + proc.stderr.decode("utf-8", "replace")[-600:])
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def subprocess_run(args, timeout, stdin):
    import subprocess
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)


def rm_containers(*names) -> None:
    if names:
        sh(["docker", "rm", "-f", *names], timeout=60)


def ip_of(name: str) -> str:
    code, out, err = sh(["docker", "inspect", "-f",
                         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name])
    # 双网容器取 10.88.*（研究网）地址
    addrs = [a for a in out.split() if a]
    research = [a for a in addrs if a.startswith("10.88.")]
    addr = (research or addrs or [""])[0]
    if code != 0 or not addr:
        raise ChainrunError(f"容器 {name} 无地址: {err}")
    return addr


def wait_banner(host: str, timeout: int = 40) -> bool:
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


def start_hop(hop: dict) -> bool:
    kind, name = hop["kind"], hop["name"]
    if kind == "pf":
        next_ip = ip_of(hop["next_host"])
        rm_containers(name)
        sh(["docker", "run", "-d", "--name", name, "--network", NET,
            "--cpus", "0.4", "--memory", "512m",
            "-e", f"MYHOSTNAME={name}.lab.test",
            "-e", f"RELAYHOST=[{next_ip}]:{hop['next_port']}",
            "-e", "HOPCOUNT_LIMIT=50", IMAGES["pf"]], check=True)
        return wait_banner(name)
    if kind == "ex":
        rm_containers(name)
        sh(["docker", "run", "-d", "--name", name, "--network", NET,
            "--cpus", "0.4", "--memory", "256m", IMAGES["ex"]], check=True)
        sh(["docker", "exec", name, "sed", "-i",
            f"s|^  route_list = .*|  route_list = * {hop['next_host']} byname|",
            "/etc/exim/exim.conf"], check=True)
        sh(["docker", "exec", name, "sed", "-i",
            f"s|^  port = .*|  port = {hop['next_port']}|",
            "/etc/exim/exim.conf"], check=True)
        sh(["docker", "restart", name], check=True)
        return wait_banner(name)
    if kind == "os":
        next_ip = ip_of(hop["next_host"])
        rm_containers(name)
        sh(["docker", "run", "-d", "--name", name, "--network", NET,
            "--cpus", "0.4", "--memory", "256m",
            "--entrypoint", "sleep", IMAGES["os"], "infinity"], check=True)
        conf = (f"listen on 0.0.0.0 port 25 hostname {name}.lab.test\n"
                f'action "next" relay host smtp://{next_ip}:{hop["next_port"]}\n'
                'match from any for any action "next"\n').encode()
        import subprocess
        proc = subprocess.run(
            ["docker", "exec", "-i", name, "sh", "-c",
             "cat > /etc/smtpd.conf && cp /etc/smtpd.conf /etc/mail/smtpd.conf && "
             "chmod 644 /etc/smtpd.conf /etc/mail/smtpd.conf && smtpd -n -f /etc/smtpd.conf"],
            input=conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if proc.returncode != 0:
            raise ChainrunError(proc.stderr.decode("utf-8", "replace")[-400:])
        sh(["docker", "exec", "-d", name, "sh", "-c",
            "smtpd -d -v -f /etc/smtpd.conf > /tmp/smtpd.log 2>&1"], check=True)
        return wait_banner(name)
    raise ChainrunError(f"未知跳类型 {kind}")


def start_chain(plan: list[dict]) -> list[str]:
    """倒序启动：末跳先起（它的地址被前跳解析）。"""
    started = []
    for hop in reversed(plan):
        if not start_hop(hop):
            raise ChainrunError(f"{hop['name']} SMTP banner 超时")
        started.append(hop["name"])
    return started


# ---------------------------------------------------------------- 发送与抓取

def smtp_send_to(server: str, rcpt: str, ev_input: str, ev_transcript: str) -> dict:
    code, out, err = sh([
        "docker", "exec", "msl-client", "python3", "/opt/research/lib/smtp_send.py",
        "--server", server, "--port", "25",
        "--mail-from", "alice@lab.test", "--rcpt-to", rcpt,
        "--input", ev_input, "--transcript", ev_transcript,
    ], timeout=120)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"accepted": False, "raw": (out or err)[-200:]}


FETCH_MAILPIT = '''
import json, sys, time, urllib.request
token, out_path = sys.argv[1], sys.argv[2]
for _ in range(12):
    try:
        r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=100", timeout=5)
        msgs = json.loads(r.read()).get("messages", [])
        cands = []
        # 快路径：Subject 精确等于 token（diffrun/sigprobe2 族种子）
        for m in msgs:
            if token == (m.get("Subject") or ""):
                raw = urllib.request.urlopen(
                    "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
                if token.encode() in raw:
                    cands.append((m.get("Created") or "", raw))
        # 慢路径：头区可能被终结、Subject 沉没——按原始字节匹配最近 40 封
        if not cands:
            for m in msgs[:40]:
                raw = urllib.request.urlopen(
                    "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
                if token.encode() in raw:
                    cands.append((m.get("Created") or "", raw))
        # 重跑同名 case 时取最新一封（按 Created 排序）
        if cands:
            cands.sort(key=lambda x: x[0], reverse=True)
            open(out_path, "wb").write(cands[0][1])
            print("OK", len(cands[0][1])); sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
'''


def fetch_capture(case_id: str, out_container_path: str, host_path: Path) -> bytes | None:
    for _ in range(3):
        code, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                           case_id, out_container_path],
                          timeout=120, stdin=FETCH_MAILPIT.encode())
        if out.strip().startswith("OK"):
            return host_path.read_bytes() if host_path.exists() else None
        time.sleep(1)
    return None


# ---------------------------------------------------------------- 行装配

def _vector(ev_path: str, stored: bytes, arm: str, chain: dict,
            cid: str | None) -> dict:
    vec = {
        "dkim": verdicts.file_verdicts(ev_path),
        "ar": verdicts.ar_verdicts(stored) if arm == "exec" else {},
        "milter_rspamd": "not-collected",
        "envelope": {},
        "chain": chain,
        "events": [],
    }
    if arm == "exec":
        mid = message_id_from_raw(stored)
        if mid == f"{cid}@lab.test":
            vec["milter_rspamd"] = verdicts.milter_rspamd(cid, message_id=f"<{mid}>")
        else:
            vec["milter_rspamd"] = "not-collected"  # 共享 Message-ID，日志无法区分臂
        vec["envelope"] = verdicts.imap_envelope(cid)
    return vec


def _emit(stage: Path, rows: list, known: set) -> None:
    (stage / "matrix-so-far.json").write_text(
        json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    (stage / "known.json").write_text(
        json.dumps(sorted(known), ensure_ascii=False, indent=1), encoding="utf-8")


def _log(stage: Path, msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with (stage / "progress.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


# ---------------------------------------------------------------- Gap 1 活动门与预检

def gap1_recent_activity(minutes: int = 45) -> list[str]:
    """Gap 1 vuln-amplify 工作流的活动痕迹：w5-* 产物目录与 Gramfuzz 工具树的近期 mtime。"""
    marks, cutoff = [], time.time() - minutes * 60
    for run_dir in sorted(RUN_ROOT.glob("w5-*")):
        for f in run_dir.rglob("*"):
            try:
                if f.is_file() and f.stat().st_mtime > cutoff:
                    marks.append(str(f))
                    break
            except OSError:
                continue
    gf = Path("/mnt/e/Gramfuzz")
    if gf.is_dir():
        for f in gf.rglob("*.py"):
            try:
                if f.stat().st_mtime > cutoff:
                    marks.append(str(f))
                    break
            except OSError:
                continue
    return marks


def stack_preflight() -> list[str]:
    problems = []
    for c in _REQUIRED_CONTAINERS:
        code, _, _ = sh(["docker", "exec", c, "true"], timeout=20)
        if code != 0:
            problems.append(f"容器未运行: {c}")
    return problems


# ---------------------------------------------------------------- 主执行

def _send_one(stage: Path, ev_stage: str, seed: Seed, cid: str, raw: bytes,
              hop1: str, arm: str) -> dict:
    (stage / f"{cid}.eml").write_bytes(raw)
    rcpt = "capture@lab.test" if arm == "capture" else "bob@lab.test"
    sent = smtp_send_to(hop1, rcpt,
                        f"{ev_stage}/{cid}.eml", f"{ev_stage}/{cid}.smtp.txt")
    stored = None
    if sent.get("accepted"):
        host_stored = stage / f"{cid}.stored.eml"
        if arm == "capture":
            stored = fetch_capture(cid, f"{ev_stage}/{cid}.stored.eml", host_stored)
        else:
            stored = verdicts.imap_fetch(cid, f"{ev_stage}/{cid}.stored.eml", host_stored)
    if stored is not None:
        chain = {"hops": None, "arm": arm,
                 "smtp_code": (sent.get("reply") or "")[:3],
                 "delivered": True}
        vec = _vector(f"{ev_stage}/{cid}.stored.eml", stored, arm, cid, chain)
        row = {
            "seed": seed.name, "sequence": None, "arm": arm,
            "smtp_code": (sent.get("reply") or "")[:3],
            "smtp": (sent.get("reply") or "")[:60],
            "delivered": True,
            "stored_path": f"{cid}.stored.eml",
            "input_sha256": sha256_bytes(raw),
            "facts": trace_facts(stored, relay_markers=CHAIN_MARKERS),
            "verdicts": vec,
        }
    else:
        row = {
            "seed": seed.name, "sequence": None, "arm": arm,
            "smtp_code": (sent.get("reply") or "")[:3],
            "smtp": (sent.get("reply") or "")[:60],
            "delivered": False,
            "stored_path": None,
            "input_sha256": sha256_bytes(raw),
            "facts": {},
            "verdicts": {},
            "smtp_raw": (sent.get("raw") or "")[-120:],
        }
    return row


def run_chain(run_id: str, sequences: dict[str, tuple[str, ...]] | None = None,
              seed_names: list[str] | None = None,
              arms: tuple[str, ...] = ("capture", "exec"),
              gap1_clear: bool = False, limit: int | None = None) -> dict:
    stage = RUN_ROOT / run_id / "chain"
    stage.mkdir(parents=True, exist_ok=True)
    ev_stage = f"{EVIDENCE_ROOT}/{run_id}/chain"

    problems: list[str] = []
    if not gap1_clear:
        marks = gap1_recent_activity()
        if marks:
            raise ChainrunError(
                "检测到 Gap 1 近期活动（" + "; ".join(marks[:3]) +
                "）——按计划协调规则让行；确已协调好则传 gap1_clear=True。")
    problems += stack_preflight()

    names = seed_names or list(SEEDS)
    if limit:
        names = names[:limit]
    seq_map = dict(SINGLE_SEQUENCES)
    seq_map.update(sequences or SEQUENCES_V0)

    known_path = stage / "known.json"
    known = set(json.loads(known_path.read_text(encoding="utf-8"))) if known_path.exists() else set()
    rows: list[dict] = []

    # ---- norelay 臂（不起容器；文件级判决基线）----
    for name in names:
        seed = SEEDS[name]
        cid = case_id(name, "norelay", "norelay")
        raw = seed.build(cid)
        check_seed_corpus(seed, raw)
        (stage / f"{cid}.eml").write_bytes(raw)
        row = {
            "seed": name, "sequence": "norelay", "arm": "norelay",
            "smtp_code": None, "delivered": None,
            "stored_path": f"{cid}.eml", "input_sha256": sha256_bytes(raw),
            "facts": trace_facts(raw, relay_markers=CHAIN_MARKERS),
            "verdicts": {"dkim": verdicts.file_verdicts(f"{ev_stage}/{cid}.eml"),
                         "ar": {}, "milter_rspamd": "not-collected",
                         "envelope": {}, "chain": {"arm": "norelay"}, "events": []},
        }
        key = known_key(row)
        row["known"] = key in known
        known.add(key)
        rows.append(row)
        _log(stage, f"norelay {name}: " + json.dumps(row["verdicts"]["dkim"]))
    _emit(stage, rows, known)

    # ---- 链臂（每序列起容器 → 控制信 → 种子 → 计数探针 → 拆除）----
    for seq_name, kinds in seq_map.items():
        if problems and not stack_preflight_pass():
            break
        for arm in arms:
            host, port = ARM_ENDPOINTS[arm]
            plan = build_hop_plan(kinds, host, port, seq_name)
            try:
                started = start_chain(plan)
            except ChainrunError as exc:
                problems.append(f"{seq_name}/{arm}: {exc}")
                rm_containers(*[h["name"] for h in plan])
                continue
            try:
                # 控制信：v00 N=1 全链投递且 Received 增量 = 期望
                ctl_cid = case_id("ctl-v00", seq_name, arm)
                ctl_raw = build_control("v00-plain", 1, ctl_cid)
                ctl_row = _send_one(stage, ev_stage, SEEDS["v00-plain"],
                                    ctl_cid, ctl_raw, plan[0]["name"], arm)
                # 控制信行用独立 seed 标识，避免与常规 v00-plain 行同键
                ctl_row.update({"seed": "ctl-v00", "sequence": seq_name, "control": True})
                delta_ok = (ctl_row["delivered"] and
                            ctl_row["facts"].get("received_zone_total") ==
                            1 + expected_relay_delta(len(kinds), arm))
                if not delta_ok:
                    problems.append(
                        f"{seq_name}/{arm}: 控制信不符 "
                        f"delivered={ctl_row['delivered']} "
                        f"received={ctl_row['facts'].get('received_zone_total')}")
                    rows.append(ctl_row)
                    _emit(stage, rows, known)
                    continue  # 停修仪器，不带病跑矩阵
                rows.append(ctl_row)
                _log(stage, f"{seq_name}/{arm} 控制信通过 "
                      f"(received={ctl_row['facts']['received_zone_total']})")

                # 种子矩阵
                for name in names:
                    seed = SEEDS[name]
                    cid = case_id(name, seq_name, arm)
                    raw = seed.build(cid)
                    check_seed_corpus(seed, raw)
                    try:
                        row = _send_one(stage, ev_stage, seed, cid, raw,
                                        plan[0]["name"], arm)
                    except ChainrunError as exc:
                        problems.append(f"{cid}: {exc}")
                        continue
                    row["sequence"] = seq_name
                    key = known_key(row)
                    row["known"] = key in known
                    known.add(key)
                    rows.append(row)
                    _log(stage, f"{cid}: {row['smtp_code']} "
                          f"delivered={row['delivered']} "
                          + json.dumps((row.get("verdicts") or {}).get("dkim", {}),
                                       ensure_ascii=False))
                    _emit(stage, rows, known)
                    time.sleep(SEND_INTERVAL)

                # 计数组合探针（只记录，不设断言——分析归 chainflip/RECORD）
                for variant, n in THRESHOLD_PROBES:
                    cid = case_id(f"thr-{variant}-n{n}", seq_name, arm)
                    raw = build_control(variant, n, cid)
                    row = _send_one(stage, ev_stage, SEEDS[variant], cid, raw,
                                    plan[0]["name"], arm)
                    row.update({"sequence": seq_name,
                                "seed": f"thr-{variant}-n{n}",  # 阈值探针独立 seed，避免与常规行同键
                                "threshold_probe": f"{variant}/n={n}"})
                    key = known_key(row)
                    row["known"] = key in known
                    known.add(key)
                    rows.append(row)
                    _log(stage, f"{cid}: {row['smtp_code']} "
                          f"delivered={row['delivered']} "
                          f"received={(row.get('facts') or {}).get('received_zone_total')}")
                    _emit(stage, rows, known)
                    time.sleep(SEND_INTERVAL)
            finally:
                rm_containers(*[h["name"] for h in plan])

    (stage / "matrix.json").write_text(
        json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    (stage / "gate.json").write_text(json.dumps({
        "stage": "chain", "passed": not problems, "problems": problems,
        "counts_as_finding": False,
        "note": "rows=" + str(len(rows)) + " seeds=" + str(len(names)) +
                " sequences=" + str(len(seq_map)) + " arms=" + ",".join(arms),
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"passed": not problems, "problems": problems, "rows": len(rows)}


def stack_preflight_pass() -> bool:
    return not stack_preflight()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--sequences", help="逗号分隔的序列名（默认 9 对 + 3 单跳）")
    parser.add_argument("--seeds", help="逗号分隔的种子名（默认全部 23）")
    parser.add_argument("--arms", default="capture,exec")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--gap1-clear", action="store_true",
                        help="确认已与 Gap 1 工作流协调好栈窗口")
    args = parser.parse_args()
    seqs = None
    if args.sequences:
        seqs = {}
        for s in args.sequences.split(","):
            seqs[s] = SEQUENCES_V0.get(s) or SINGLE_SEQUENCES.get(s) or tuple(s.split("-"))
    report = run_chain(
        args.run_id, sequences=seqs,
        seed_names=args.seeds.split(",") if args.seeds else None,
        arms=tuple(a for a in args.arms.split(",") if a),
        gap1_clear=args.gap1_clear, limit=args.limit)
    print(f"chain gate passed={report['passed']}")
    for p in report["problems"]:
        print(" -", p)
