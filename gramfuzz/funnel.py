"""语法差分漏斗：corpus → stage1（本地三 parser 批量差分）→ stage2（中继/签名/消费）→ report。

    python3 -m gramfuzz.funnel <run_id> --phase corpus [--smoke | --per-entry N]
    python3 -m gramfuzz.funnel <run_id> --phase stage1
    python3 -m gramfuzz.funnel <run_id> --phase stage2   # 三臂：中继/签名/IMAP
    python3 -m gramfuzz.funnel <run_id> --phase report   # 任务 7 未实现

终点是 candidates.json——实验室确认的差分清单，作为 4-5 号工作（真实服务
验证与披露）的决策门。本引擎不做任何对外动作。

stage-1 判定元组（只在 _tuple 一处定义）：(received_count, from_in_headers,
field_count)，field_count 一律为去重字段名数。任何两家不一致 = 差分；
parser 报错与非报错也算不一致（统一折叠为 ("error",)）。

迁出说明（2026-10-03 自 MailSecLab research/lib/gramfuzz.py 迁出）：
- 文法入口（grammar/entries.json）、RFC 文本（rfc/）、批量探针（parsers/）
  改用本仓库目录（lab.py 的 GRAMMAR_DIR/RFC_DIR/PARSERS_DIR）；运行产物
  目录与共享设施仍来自实验室（lab.py 的 RUN_ROOT/diffrun/corpus_check，
  /evidence 容器挂载决定了产物必须落在实验室 results/ 下）。
- 容器里的 /opt/research 挂载不再承载本工具的批量探针（迁出后挂载源只剩
  单样本 parse.*）：每次 stage1 开头把三份探针 docker cp 进各自容器的
  /tmp，语料仍走 /evidence（python/go）或 tar（node，无 /evidence 挂载）。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gramfuzz.abnf import Grammar
from gramfuzz.gramgen import build_message, generate_sample
from gramfuzz.grammut import PriorityTable, mutate
from gramfuzz.lab import (GRAMMAR_DIR, MAILSECLAB_ROOT, PARSERS_DIR, RFC_DIR,
                          RUN_ROOT, TARGETS_JSON, corpus_check, diffrun,
                          reference, verify_file)

# rfc2045 必须在列表里：8601 的 value 规则引用它（abnf 审查线，见 105f2bf）。
RFCS = [str(RFC_DIR / ("rfc%s.txt" % n))
        for n in ("5322", "5321", "8601", "6376", "8617", "6532", "2045")]

FRESH_PER_ENTRY = 1500        # 全量规模（模块常量，便于整批调小试跑）
MUTATED_PER_ENTRY = 1500
SMOKE_PER_KIND = 20           # --smoke：每入口 fresh/mutated 各 20
SEED_CAP_PER_ENTRY = 60000    # 生成失败保护上限：到达即止，该入口照记零语料
CORPUS_SEED = 20261003        # corpus RNG 主种子（重放按 seed 而不是按时间）

# 批量探针交付路径：宿主侧来自本仓库 parsers/，容器侧一律 /tmp——迁出后
# /opt/research 挂载里已没有 parse_batch.*，不能再借实验室目录进容器。
PY_PROBE_HOST = PARSERS_DIR / "parse_batch.py"
GO_PROBE_HOST = PARSERS_DIR / "parse_batch.go"
NODE_PROBE_HOST = PARSERS_DIR / "parse_batch.js"
PY_PROBE_CTR = "/tmp/gf-pb.py"
GO_PROBE_CTR = "/tmp/gf-pb.go"
NODE_PROBE_CTR = "/tmp/gf-pb.js"
NODE_TMP_CORPUS = "/tmp/corpus"

# stage1 三 parser 的容器名：TARGETS_JSON（实验室 research/diffrun-targets.json）
# 存在时以其 parse.<target>.container 为准，缺文件时用历史默认值。
_DEFAULT_CONTAINERS = {"python": "msl-client", "go": "msl-verifiers",
                       "node": "parser-node"}

# ---- phase: stage2（任务 6 三臂）----

# 签名验证臂的对象：identity / AR / DKIM 条目（计划三臂表 (b)）。
SIGN_ENTRIES = ("from", "obs-from", "sender", "reply-to", "return-path",
                "resent-from", "authres", "dkim-tags")
SIGN_CAP = 100
# 消费臂对象：from 族（计划三臂表 (c)）。
IMAP_ENTRIES = ("from", "obs-from", "sender", "reply-to", "resent-from")
IMAP_CAP = 40

# 每台中继的存档由 msl-mailpit 收信时自加一条 Received（控制信验证过格式）；
# 用于确认按主题抓到的存档确实走了该目标（w3 sigprobe2 的 fetch 竞态教训）。
RELAY_MARKERS = {"postfix": b"from auth-postfix.lab.test",
                 "exim": b"from exim.lab.test",
                 "osmtpd": b"from opensmtpd.lab.test"}

# DKIM：cal 选择器（w1 密钥，DNS 记录在 msl-dns 常驻）。
DKIM_KEY = MAILSECLAB_ROOT / "results" / "research" / "w1-20261001a" / "keys" / "priv.pem"
SIGN_HEADERS = ["from", "to", "subject", "date"]

# KB2 正确性锚：对 strict 签名后顶部注入一条 obs Received，文件级四验证器
# 必须复现 w3 sigprobe2 s2-norelay 行（dkimpy 拒解析 / 其余三家 pass）。
KB2_INJECT = (b"Received : from x.lab.test by y.lab.test; "
              b"Sat, 3 Oct 2026 00:00:00 +0000\r\n")
KB2_EXPECT = {"dkimpy": "parse-error", "perl": "pass", "go": "pass",
              "rspamd": "pass"}

SEND_INTERVAL = 0.8            # 每封之间 ≥0.8s（任务纪律）

# 中继标记感知的恢复抓取：按主题抓取可能落在同 case 的其他中继副本上
# （w4 smoke 实测：postfix 规范化保住 Subject、exim/osmtpd 主题沉没的
# 混合形态，主题优先逻辑永远命中 postfix 那份）。恢复路径扫最近消息的
# 原始字节，同时要求 case 字节与中继标记都在场，取最新。
_RECOVERY_FETCH = r"""
import json, sys, time, urllib.request
case_id, marker, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
for _ in range(10):
    try:
        msgs = json.loads(urllib.request.urlopen(
            "http://msl-mailpit:8025/api/v1/messages?limit=50", timeout=5).read()
        ).get("messages", [])
        cands = []
        for m in msgs:
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
            if case_id.encode() in raw and marker.encode() in raw:
                cands.append((m.get("Created") or "", raw))
        if cands:
            cands.sort(key=lambda x: x[0], reverse=True)
            open(out_path, "wb").write(cands[0][1])
            print("OK", len(cands[0][1]))
            sys.exit(0)
    except Exception:
        pass
    time.sleep(1.2)
print("MISS")
"""

# IMAP 消费臂的两段探针（在 msl-client 容器内跑；_argv 传 JSON，输出纯 JSON）。
_IMAP_PROBE_FETCH = r"""
import base64, imaplib, json, sys, time

def _flat(x, out=None):
    if out is None:
        out = []
    if isinstance(x, (tuple, list)):
        for i in x:
            _flat(i, out)
    elif isinstance(x, bytes):
        out.append(x)
    return out

cases = json.loads(sys.argv[1])
res = {}
try:
    m = imaplib.IMAP4("msl-dovecot", 143)
    m.login("bob", "lab-bob")
    m.select("INBOX", readonly=True)
    for case in cases:
        rec = {"uid": None, "locator": None}
        try:
            # 主定位：SEARCH HEADER X-CASE-ID。头区被 obs 行终结的语料，
            # X-Case-ID 已沉入正文，HEADER 检索不到——这个事实本身是信号
            # （locator=body），回退用 TEXT（头+正文）定位。
            for crit, label in ((("HEADER", "X-CASE-ID", '"%s"' % case), "header"),
                                (("TEXT", '"%s"' % case), "body")):
                for _ in range(5):
                    typ, data = m.uid("SEARCH", *crit)
                    uids = data[0].split() if data and data[0] else []
                    if uids:
                        uid = uids[-1].decode()
                        rec["uid"] = uid
                        rec["locator"] = label
                        typ, msg = m.uid("FETCH", uid, "(ENVELOPE)")
                        rec["envelope_parts"] = [base64.b64encode(p).decode("latin-1")
                                                 for p in _flat(msg)]
                        typ, msg = m.uid("FETCH", uid, "(BODY.PEEK[])")
                        rec["body_parts"] = [base64.b64encode(p).decode("latin-1")
                                             for p in _flat(msg)]
                        break
                    time.sleep(1.2)
                if rec["uid"]:
                    break
        except Exception as exc:
            rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        res[case] = rec
    m.logout()
except Exception as exc:
    res["_conn_error"] = "%s: %s" % (type(exc).__name__, exc)
print(json.dumps(res))
"""

_IMAP_PROBE_SEARCH = r"""
import base64, json, socket, sys

queries = json.loads(sys.argv[1])  # [[qid, addr_b64], ...]
res = {}
try:
    s = socket.create_connection(("msl-dovecot", 143), timeout=30)
    f = s.makefile("rb")
    f.readline()

    def raw(tag, payload):
        s.sendall(tag + b" " + payload + b"\r\n")
        chunks = []
        while True:
            line = f.readline()
            if not line:
                break
            chunks.append(line)
            if line.startswith(tag + b" "):
                break
        return b"".join(chunks)

    raw(b"a1", b"LOGIN bob lab-bob")
    raw(b"a2", b"SELECT INBOX")
    n = 3
    for qid, addr_b64 in queries:
        addr = base64.b64decode(addr_b64).replace(b"\\", b"\\\\").replace(b'"', b'\\"')
        try:
            out = raw(b"a%d" % n,
                      b'UID SEARCH CHARSET UTF-8 HEADER FROM "' + addr + b'"')
            n += 1
            uids = []
            for line in out.split(b"\r\n"):
                if line.startswith(b"* SEARCH"):
                    uids = line[len(b"* SEARCH"):].split()
                    break
            lines = [ln for ln in out.split(b"\r\n") if ln]
            res[qid] = {"uids": [u.decode() for u in uids],
                        "status": lines[-1].decode("utf-8", "replace")[:100]
                        if lines else ""}
        except Exception as exc:
            res[qid] = {"error": str(exc)}
    try:
        raw(b"a%d" % n, b"LOGOUT")
    except Exception:
        pass
    s.close()
except Exception as exc:
    res["_conn_error"] = "%s: %s" % (type(exc).__name__, exc)
print(json.dumps(res))
"""


def _entries() -> list[dict]:
    return json.loads((GRAMMAR_DIR / "entries.json")
                      .read_text(encoding="utf-8"))["entries"]


def _containers() -> dict[str, str]:
    if TARGETS_JSON.exists():
        cfg = json.loads(TARGETS_JSON.read_text(encoding="utf-8")).get("parse", {})
        return {k: cfg.get(k, {}).get("container", v)
                for k, v in _DEFAULT_CONTAINERS.items()}
    return dict(_DEFAULT_CONTAINERS)


# ---- phase: corpus ----

def phase_corpus(run_id: str, pt: PriorityTable,
                 fresh_per: int = FRESH_PER_ENTRY,
                 mutated_per: int = MUTATED_PER_ENTRY) -> dict:
    g = Grammar.load_files(RFCS)
    stage = RUN_ROOT / run_id / "gramfuzz"
    corpus = stage / "corpus"
    if corpus.exists():       # corpus phase 是该目录的唯一权威：先清再写
        shutil.rmtree(corpus)
    corpus.mkdir(parents=True, exist_ok=True)
    rng = random.Random(CORPUS_SEED)
    index = []
    for entry in _entries():
        symbol, prefix = entry["symbol"], entry.get("prefix") or ""
        made_fresh = made_mutated = seed = 0
        t0 = time.time()
        while (made_fresh < fresh_per or made_mutated < mutated_per) \
                and seed < SEED_CAP_PER_ENTRY:
            s = generate_sample(g, symbol, seed)
            seed += 1
            if s is None:
                continue
            gen = (prefix + s).encode("latin-1")
            if made_fresh < fresh_per:
                mutated, op = False, None
                case_id = "gf-%s-fresh-%04d" % (entry["name"], made_fresh)
            else:
                mutated = True
                op = pt.pick(rng)
                case_id = "gf-%s-%s-%04d" % (entry["name"], op, made_mutated)
            # case_id 先定——Subject/Message-ID/X-Case-ID 一次写对，mailpit
            # 按主题抓取依赖它，绝不占位后改写。
            base = build_message(gen, case_id)
            if corpus_check(base):
                continue      # 生成伪影（双 CRLF 等）直接丢弃，F1 纪律
            raw = mutate(base, rng, ops=(op,)) if mutated else base
            if raw is None:
                continue      # 该算子对此样本不可作用
            # 变异样本不再过 corpus_check：结构异常（sink/折叠/重复实例）
            # 正是被测信号。
            (corpus / ("%s.eml" % case_id)).write_bytes(raw)
            index.append({"case": case_id, "entry": entry["name"],
                          "mutated": mutated, "op": op, "gen_bytes": gen.hex(),
                          "input_sha256": hashlib.sha256(raw).hexdigest()})
            if mutated:
                made_mutated += 1
            else:
                made_fresh += 1
        print("entry %-12s fresh=%-5d mutated=%-5d seeds=%-6d %.1fs"
              % (entry["name"], made_fresh, made_mutated, seed, time.time() - t0),
              flush=True)
    (stage / "corpus-index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    print("corpus:", len(index), "files ->", corpus)
    return {"files": len(index)}


# ---- phase: stage1 ----

def _tuple(v: dict | None) -> tuple:
    """stage-1 比较元组：唯一的口径定义处。报错折叠为 ("error",)。"""
    if v is None or "error" in v:
        return ("error",)
    return (v["received_count"], v["from_in_headers"], v["field_count"])


def _parse_probe_output(out: str) -> dict:
    rows = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict) and "case" in r:
            rows[r["case"]] = r
    return rows


def _probe(cmd: list[str], what: str, timeout: int = 1800) -> dict:
    code, out, err = diffrun.sh(cmd, timeout=timeout)
    rows = _parse_probe_output(out)
    if not rows:
        raise RuntimeError("%s 批量探针无输出（code=%d）：%s"
                           % (what, code, (err or out)[-500:]))
    return rows


def _deliver_probes(containers: dict[str, str]) -> None:
    """把三份批量探针 docker cp 进各自容器——每次 phase_stage1 开头一次。

    迁出前探针借 MailSecLab 的 /opt/research 挂载进容器；迁出后挂载源只剩
    单样本 parse.*，探针改由本仓库 parsers/ 直接 cp 到容器 /tmp。
    """
    for container, src, dst in (
            (containers["python"], PY_PROBE_HOST, PY_PROBE_CTR),
            (containers["go"], GO_PROBE_HOST, GO_PROBE_CTR),
            (containers["node"], NODE_PROBE_HOST, NODE_PROBE_CTR)):
        code, _, err = diffrun.sh(["docker", "cp", str(src),
                                   "%s:%s" % (container, dst)], timeout=120)
        if code != 0:
            raise RuntimeError("docker cp %s -> %s:%s 失败：%s"
                               % (src, container, dst, err.strip()))


def _run_python(ev_corpus: str, container: str) -> dict:
    # msl-client 同时挂载 /evidence，语料走 /evidence 路径；脚本走 cp 副本。
    return _probe(["docker", "exec", container, "python3", PY_PROBE_CTR,
                   ev_corpus], "python")


def _run_go(ev_corpus: str, container: str) -> dict:
    # msl-verifiers 也同时挂载两目录（实测），无需 tar：go run 走 w3 验证过的
    # 离线标准库路径，脚本在 /tmp 同样可编译执行（2026-10-03 迁出时实测）。
    return _probe(["docker", "exec", container, "go", "run", GO_PROBE_CTR,
                   ev_corpus], "go")


def _run_node(corpus: Path, container: str) -> dict:
    # parser-node 只挂载 /opt/research、没有 /evidence（实测）：语料 tar 一次
    # 送进容器 /tmp，绝不逐文件 exec；脚本走 cp 副本。
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "corpus.tgz"
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(corpus, arcname="corpus")
        diffrun.sh(["docker", "exec", container, "rm", "-rf",
                    NODE_TMP_CORPUS], timeout=120)
        with open(tgz, "rb") as fh:
            subprocess.run(["docker", "exec", "-i", container,
                            "tar", "-xzf", "-", "-C", "/tmp"],
                           stdin=fh, check=True, timeout=1800)
    return _probe(["docker", "exec", "-e", "NODE_PATH=/app/node_modules",
                   container, "node", NODE_PROBE_CTR, NODE_TMP_CORPUS], "node")


def phase_stage1(run_id: str) -> dict:
    stage = RUN_ROOT / run_id / "gramfuzz"
    corpus = stage / "corpus"
    ev_corpus = "/evidence/%s/gramfuzz/corpus" % run_id
    index_path = stage / "corpus-index.json"
    if not index_path.exists():
        raise RuntimeError("缺少 %s——先跑 --phase corpus" % index_path)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if not index:
        raise RuntimeError("corpus-index.json 为空：没有任何可判定的样本")
    containers = _containers()
    _deliver_probes(containers)
    views = {"python": _run_python(ev_corpus, containers["python"]),
             "go": _run_go(ev_corpus, containers["go"]),
             "node": _run_node(corpus, containers["node"])}
    for target, view in views.items():
        if len(view) < int(len(index) * 0.95):
            raise RuntimeError("%s 探针只覆盖 %d/%d 个 case——探针半途崩溃，"
                               "不带病出结果" % (target, len(view), len(index)))
    rows, survivors = [], []
    for item in index:
        case = item["case"]
        tv = {k: _tuple(v.get(case)) for k, v in views.items()}
        diff = len(set(tv.values())) > 1
        rows.append(dict(item, views=tv, stage1_diff=diff))
        if diff:
            survivors.append(case)
    (stage / "stage1.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    (stage / "survivors.json").write_text(
        json.dumps(survivors, indent=1), encoding="utf-8")
    op_stats = Counter(r["op"] for r in rows if r["stage1_diff"])
    entry_stats = Counter(r["entry"] for r in rows if r["stage1_diff"])
    summary = {"total": len(rows), "survivors": len(survivors),
               "by_op": dict(op_stats), "by_entry": dict(entry_stats)}
    (stage / "stage1-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print("stage1: %d/%d survivors" % (len(survivors), len(rows)))
    return summary


# ---- phase: stage2 ----

def classify(row: dict) -> list[str]:
    """按「首个分歧动词」归系列；跨系列记链（任务 6 Step 6.5，计划原文）。

    P 识别差分：stage1 三家 views 元组不一致。
    T 变换差分：中继间 gen_preserved 不一致，或全部不保留（生成头被改写）。
    X 信任差分：四验证器判定集合不一致（文件级 + postfix 路径合并视图）。
    D 展示差分：IMAP ENVELOPE From 槽 ≠ 头区第一 From 实例。
    """
    series = []
    if len({tuple(v) for v in row.get("views", {}).values()}) > 1:
        series.append("P")
    relay = row.get("relay", {})
    preserved = [t.get("gen_preserved") for t in relay.values() if t.get("captured")]
    if len(set(preserved)) > 1 or (preserved and not any(preserved)):
        series.append("T")
    if len({v for v in row.get("verdicts", {}).values()}) > 1:
        series.append("X")
    if row.get("envelope_from") and row.get("envelope_from") != row.get("header_from_first"):
        series.append("D")
    return series or ["U"]


def _dedup_and_cap(rows_by_case: dict, survivors: list[str], cap: int) -> list[str]:
    """语义去重 + 按入口分层抽样，硬上限 cap（计划 Step 6.2）。

    去重键 = (entry, views 元组集合)。只在超上限时启用：上限内的 smoke 全量
    测量（任务 6.2 明确「逐个 × 3 目标」），去重与分层服务于全量 campaign
    的规模控制，byte 级不同的样本在中继臂可能有不同命运，不做无谓丢弃。
    """
    if len(survivors) <= cap:
        return list(survivors)
    seen, uniq = set(), []
    for case in survivors:
        r = rows_by_case[case]
        key = (r["entry"], tuple(sorted(tuple(v) for v in r["views"].values())))
        if key not in seen:
            seen.add(key)
            uniq.append(case)
    return _stratified_cap(uniq, {c: rows_by_case[c]["entry"] for c in uniq}, cap)


def _stratified_cap(cases: list[str], entry_of: dict, cap: int) -> list[str]:
    """按入口等额轮流抽样到 cap（campaign 规模控制；上限内原样返回）。"""
    if len(cases) <= cap:
        return list(cases)
    by_entry: dict[str, list[str]] = {}
    for case in cases:
        by_entry.setdefault(entry_of[case], []).append(case)
    out = []
    while len(out) < cap:
        progressed = False
        for entry in sorted(by_entry):
            if by_entry[entry]:
                out.append(by_entry[entry].pop(0))
                progressed = True
                if len(out) >= cap:
                    break
        if not progressed:
            break
    return out


# ---- 臂 (a)：中继捕获 ----

def _relay_one(run_id: str, stage: Path, case: str, target: str,
               server: str, port: int, raw: bytes, gen: bytes,
               problems: list[str]) -> dict:
    """一个 case × 一台中继：smtp_arm 发送 + 标记核对 + gen_preserved。

    smtp_arm 自带 corpus_check 门槛（任务纪律，不绕过）：语料伪影会以
    {"error": ...} 记录并进 problems，不静默、不记阴性。
    """
    tdir = stage / "relay" / target
    tdir.mkdir(parents=True, exist_ok=True)
    ev_t = "/evidence/%s/gramfuzz/relay/%s" % (run_id, target)
    try:
        r = diffrun.smtp_arm(tdir, ev_t, case, target, server, port, raw, "relay")
    except Exception as exc:
        problems.append("%s/%s: smtp_arm 异常 %s" % (case, target, exc))
        return {"error": str(exc)}
    if not r.get("captured"):
        return r
    stored_path = tdir / ("%s.stored.raw" % case)
    marker = RELAY_MARKERS[target]
    # 按主题取最新可能落在同 case 的其他中继副本上（混合形态：一家保住
    # 主题、另一家主题沉没）：先用中继标记核对，不中改走标记感知恢复
    # 抓取（扫原始字节 + 标记，取最新），仍不中才记 marker-missing。
    tries = 0
    while marker not in stored_path.read_bytes() and tries < 3:
        tries += 1
        time.sleep(1.5)
        got = _marker_fetch(case, marker.decode(), stored_path,
                            "%s/%s.stored.raw" % (ev_t, case))
        if got is None:
            break
    stored = stored_path.read_bytes()
    if marker in stored:
        r["attribution"] = "ok" if tries == 0 else "ok-recovered"
        r["gen_preserved"] = gen in stored
    else:
        r["attribution"] = "marker-missing"
        r["gen_preserved"] = None
        problems.append("%s/%s: 存档缺中继标记（误抓或投递异常），gen_preserved=未知"
                        % (case, target))
    return r


def _marker_fetch(case: str, marker: str, host_path: Path,
                  container_path: str) -> bytes | None:
    """中继标记感知恢复抓取（见 _RECOVERY_FETCH 注释）。"""
    for _ in range(3):
        code, out, _ = diffrun.sh(
            ["docker", "exec", "-i", "msl-client", "python3", "-",
             case, marker, container_path],
            timeout=120, stdin=_RECOVERY_FETCH.encode())
        if out.strip().startswith("OK"):
            return host_path.read_bytes()
        time.sleep(1)
    return None


def _relay_arm(run_id: str, stage: Path, cases: list[str], index: dict,
               problems: list[str]) -> dict[str, dict]:
    """返回 case → {target: 行}（smtp 码 / captured / gen_preserved / facts）。"""
    targets, _ = diffrun.load_config()
    out: dict[str, dict] = {}
    for case in cases:
        raw = (stage / "corpus" / ("%s.eml" % case)).read_bytes()
        gen = bytes.fromhex(index[case]["gen_bytes"])
        out[case] = {}
        for target, (server, port) in targets.items():
            row = _relay_one(run_id, stage, case, target, server, port, raw,
                             gen, problems)
            out[case][target] = row
            print(json.dumps({"case": case, "target": target,
                              "code": row.get("smtp_code"),
                              "captured": row.get("captured"),
                              "gen": row.get("gen_preserved"),
                              "attr": row.get("attribution")}), flush=True)
            time.sleep(SEND_INTERVAL)
    return out


# ---- 臂 (b)：签名验证（KB2 锚先行）----

def _sign_template(case_id: str) -> bytes:
    return ("\r\n".join([
        "From: Bank Security <security@lab.test>",
        "To: bob@lab.test",
        "Date: Sat, 3 Oct 2026 23:59:00 +0000",
        "Subject: %s" % case_id,
        "Message-ID: <%s@lab.test>" % case_id,
        "X-Case-ID: %s" % case_id,
    ]) + "\r\n\r\nPlease confirm the payment.\r\n").encode()


def _slim_verdicts(verdicts: dict) -> dict:
    """verify_file 全量记录 → 可入 stage2.json 的瘦身版（stdout 截 300 字）。"""
    out = {}
    for tool, rec in verdicts.items():
        slim = {"status": rec.get("status")}
        if tool == "rspamd":
            slim.update({k: rec.get(k) for k in ("action", "score")})
        for k in ("stdout", "stderr"):
            if rec.get(k):
                slim[k] = rec[k][:300]
        out[tool] = slim
    return out


def _statuses(verdicts: dict) -> dict:
    return {k: v.get("status") for k, v in verdicts.items()}


def _sign_one(run_id: str, stage: Path, sign_case: str, inject: bytes) -> dict:
    """签名模板 → 顶部注入 inject → 文件级四验证器 + 过 auth-postfix 后再验。

    s2 注入模式（w3 sigprobe2）：生成头插在 DKIM-Signature 之上，签名字节
    不变。sign_case 用独立后缀（Subject/X-Case-ID 同名），mailpit 里与
    中继臂同 case 的存档不混淆。
    """
    sign_dir = stage / "sign"
    sign_dir.mkdir(parents=True, exist_ok=True)
    ev_sign = "/evidence/%s/gramfuzz/sign" % run_id
    signed, _meta = reference.sign(_sign_template(sign_case), DKIM_KEY,
                                   list(SIGN_HEADERS), mode="relaxed",
                                   domain="lab.test", selector="cal")
    inject = inject if inject.endswith(b"\r\n") else inject + b"\r\n"
    injected = inject + signed
    (sign_dir / ("%s.eml" % sign_case)).write_bytes(injected)
    row = {"sign_case": sign_case,
           "file": _statuses(verify_file("%s/%s.eml" % (ev_sign, sign_case)))}
    r = _relay_one_sign(run_id, stage, sign_dir, ev_sign, sign_case, injected)
    row["postfix"] = r
    if r.get("captured"):
        verdicts = verify_file("%s/%s.stored.raw" % (ev_sign, sign_case))
        r["verdicts"] = _statuses(verdicts)
        r["verdicts_detail"] = _slim_verdicts(verdicts)
    return row


def _relay_one_sign(run_id: str, stage: Path, sign_dir: Path, ev_sign: str,
                    sign_case: str, injected: bytes) -> dict:
    """签名臂的 postfix 中继（smtp_send + fetch，rcpt=capture@ 走捕获路由）。"""
    try:
        return diffrun.smtp_arm(sign_dir, ev_sign, sign_case, "postfix",
                                "msl-auth-postfix", 25, injected, "sign")
    except Exception as exc:
        return {"error": str(exc)}


def _sign_arm(run_id: str, stage: Path, cases: list[str], index: dict,
              problems: list[str]) -> tuple[dict, dict[str, dict]]:
    """KB2 锚（不过则抛错停批）+ 批量签名注入。返回 (锚数据, case→sign行)。"""
    sign_dir = stage / "sign"
    sign_dir.mkdir(parents=True, exist_ok=True)
    anchor = _sign_one(run_id, stage, "gf-sign-anchor-kb2", KB2_INJECT)
    (sign_dir / "anchor-kb2.json").write_text(
        json.dumps(anchor, ensure_ascii=False, indent=1), encoding="utf-8")
    if anchor["file"] != KB2_EXPECT:
        problems.append("KB2 锚未复现：%s" % json.dumps(anchor["file"]))
        raise RuntimeError("KB2 正确性锚未复现（期望 %s，得到 %s）——接线有误，"
                           "停下修接线再跑批量"
                           % (json.dumps(KB2_EXPECT), json.dumps(anchor["file"])))
    selected = _stratified_cap(
        [c for c in cases if index[c]["entry"] in SIGN_ENTRIES],
        {c: index[c]["entry"] for c in cases}, SIGN_CAP)
    out = {}
    for case in selected:
        sign_case = "%s-sign" % case
        gen = bytes.fromhex(index[case]["gen_bytes"])
        try:
            srow = _sign_one(run_id, stage, sign_case, gen)
        except Exception as exc:
            srow = {"sign_case": sign_case, "error": str(exc)}
            problems.append("%s: 签名臂异常 %s" % (case, exc))
        if srow.get("postfix", {}).get("captured"):
            stored = (sign_dir / ("%s.stored.raw" % sign_case)).read_bytes()
            srow["postfix"]["gen_preserved"] = gen in stored
        out[case] = srow
        print(json.dumps({"case": case, "file": srow.get("file"),
                          "postfix": (srow.get("postfix") or {}).get("verdicts"),
                          "gen": (srow.get("postfix") or {}).get("gen_preserved")}),
              flush=True)
        time.sleep(SEND_INTERVAL)
    return anchor, out


# ---- 臂 (c)：IMAP 消费 ----

def _imap_tokens(parts: list[bytes]) -> list:
    """IMAP fetch 响应（文本段/字面量段交替）→ token 流。

    {n} 字面量标记后跟的整段就是该 token（保留空格/UTF-8 原样）；带引号的
    字符串处理反斜杠转义。这是 ENVELOPE 解析的唯一入口，可单测。
    """
    i, pos, out = 0, 0, []
    while i < len(parts):
        seg = parts[i]
        while pos < len(seg):
            ch = seg[pos:pos + 1]
            if ch == b" ":
                pos += 1
            elif ch in (b"(", b")"):
                out.append(ch.decode())
                pos += 1
            elif ch == b'"':
                pos += 1
                buf = bytearray()
                while pos < len(seg):
                    if seg[pos:pos + 1] == b"\\" and pos + 1 < len(seg):
                        buf += seg[pos + 1:pos + 2]
                        pos += 2
                    elif seg[pos:pos + 1] == b'"':
                        pos += 1
                        break
                    else:
                        buf += seg[pos:pos + 1]
                        pos += 1
                out.append(bytes(buf))
            else:
                j = pos
                while j < len(seg) and seg[j:j + 1] not in b' ()"':
                    j += 1
                atom = seg[pos:j]
                pos = j
                m = re.match(rb"\{(\d+)\}\r?\n?$", atom)
                if m:
                    if i + 1 >= len(parts):
                        break
                    out.append(parts[i + 1][:int(m.group(1))])
                    i += 2
                    pos = 0
                    break
                out.append(atom)
        else:
            i += 1
            pos = 0
    return out


def _nested(tokens: list) -> list:
    stack: list[list] = [[]]
    for tok in tokens:
        if tok == "(":
            stack.append([])
        elif tok == ")":
            fin = stack.pop()
            stack[-1].append(fin)
        else:
            stack[-1].append(tok)
    return stack[0]


def _find_envelope(node) -> list | None:
    """在嵌套结构里定位 ENVELOPE 关键字，返回其后的字段表。

    真实响应两种形态都出现（Dovecot 实测）：`(ENVELOPE (字段))` 里
    [b"ENVELOPE", 字段表] 相邻；`(UID 2817 ENVELOPE (字段))` 里两者是
    同一列表的相邻元素。统一规则：ENVELOPE 元素的下一个 list 即字段表。
    """
    if isinstance(node, list):
        for idx, item in enumerate(node):
            if item == b"ENVELOPE" and idx + 1 < len(node) \
                    and isinstance(node[idx + 1], list):
                return node[idx + 1]
        for child in node:
            found = _find_envelope(child)
            if found is not None:
                return found
    return None


def _addr_spec(addr) -> str | None:
    """ENVELOPE 地址结构 (name adl mailbox host) → mailbox@host（NIL 侧空）。"""
    if not (isinstance(addr, list) and len(addr) >= 4):
        return None

    def s(x):
        return None if not isinstance(x, bytes) or x == b"NIL" else x

    mbox, host = s(addr[2]), s(addr[3])
    if mbox is None and host is None:
        return None
    return ((mbox or b"") + b"@" + (host or b"")).decode("utf-8", "replace").lower()


def _envelope_from_slot(parts: list[bytes]) -> dict:
    """fetch 响应 → ENVELOPE From 槽。

    响应结构 (seq (UID n ENVELOPE (date subject from-group sender ...)))：
    _find_envelope 返回 ENVELOPE 关键字后的字段表，from = 字段表第 3 项
    （RFC 3501 env-date/env-subject/env-from 顺序）。
    """
    env_fields = _find_envelope(_nested(_imap_tokens(parts)))
    if not isinstance(env_fields, list) or len(env_fields) < 3:
        return {"error": "no-envelope"}
    addrs = env_fields[2]
    slot = None
    if isinstance(addrs, list) and addrs:
        slot = _addr_spec(addrs[0])
    return {"from_slot": slot,
            "from_group": [(_addr_spec(a) if isinstance(a, list)
                            else a.decode("utf-8", "replace")) for a in addrs]
            if isinstance(addrs, list) else None}


def _first_from_value(raw: bytes) -> str | None:
    """投递后字节流头区（首个空行前）的第一条 From 逻辑行（含折行）。"""
    zone = raw.split(b"\r\n\r\n", 1)[0]
    lines = zone.split(b"\r\n")
    for idx, line in enumerate(lines):
        if re.match(rb"(?i)^from[ \t]*:", line):
            logical = [line]
            j = idx + 1
            while j < len(lines) and lines[j][:1] in (b" ", b"\t"):
                logical.append(lines[j])
                j += 1
            return b"\r\n".join(logical).decode("latin-1", "replace")
    return None


def _addr_from_value(value: str | None) -> str | None:
    """'Bank Security <a@b>' / 垃圾值 → 用于比较的地址串（小写）。"""
    if value is None:
        return None
    v = value.split(":", 1)[1] if ":" in value else value
    v = re.sub(r"\s+", " ", v).strip()
    m = re.search(r"<([^<>]*)>", v)
    cand = m.group(1) if m else re.sub(r"\([^)]*\)", "", v).strip().strip('"')
    cand = cand.strip().lower()
    return cand or None


def _body_from_parts(parts: list[bytes]) -> bytes:
    if not parts:
        return b""
    m = re.search(rb"\{(\d+)\}\r?\n?$", parts[0])
    if m and len(parts) >= 2:
        return parts[1][:int(m.group(1))]
    return b""


def _imap_arm(run_id: str, stage: Path, cases: list[str], index: dict,
              problems: list[str]) -> dict[str, dict]:
    """from 族幸存者投递到 bob@（标准链进 Dovecot，不走 capture 路由），
    IMAP 取 ENVELOPE From 槽 + SEARCH HEADER FROM，与头区第一实例对照。"""
    imap_dir = stage / "imap"
    imap_dir.mkdir(parents=True, exist_ok=True)
    selected = _stratified_cap(
        [c for c in cases if index[c]["entry"] in IMAP_ENTRIES],
        {c: index[c]["entry"] for c in cases}, IMAP_CAP)
    accepted = []
    rows: dict[str, dict] = {}
    for case in selected:
        raw = (stage / "corpus" / ("%s.eml" % case)).read_bytes()
        gate = corpus_check(raw)
        if gate:
            # 与 smtp_arm 同一道门槛：语料伪影不发送、记 problems（任务纪律）。
            rows[case] = {"error": "corpus_check: %s" % gate}
            problems.append("%s: IMAP 臂 corpus_check 未过 %s" % (case, gate))
            continue
        code, out, err = diffrun.sh([
            "docker", "exec", "msl-client", "python3",
            "/opt/research/lib/smtp_send.py",
            "--server", "msl-auth-postfix", "--port", "25",
            "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
            "--input", "/evidence/%s/gramfuzz/corpus/%s.eml" % (run_id, case),
            "--transcript", "/evidence/%s/gramfuzz/imap/%s.smtp.txt" % (run_id, case),
        ], timeout=90)
        try:
            sent = json.loads(out)
        except json.JSONDecodeError:
            sent = {"accepted": False, "reply": (out or err)[-120:]}
        rows[case] = {"smtp_code": (sent.get("reply") or "")[:3],
                      "smtp": (sent.get("reply") or "")[:60]}
        if sent.get("accepted"):
            accepted.append(case)
        else:
            problems.append("%s: IMAP 臂 SMTP 未接受 %s" % (case, sent.get("reply")))
        time.sleep(SEND_INTERVAL)
    # 探针一：ENVELOPE + 原始字节（等 LMTP 投递，按 X-Case-ID 检索）。
    code, out, err = diffrun.sh(
        ["docker", "exec", "-i", "msl-client", "python3", "-",
         json.dumps(accepted)], timeout=600, stdin=_IMAP_PROBE_FETCH.encode())
    try:
        fetched = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except (json.JSONDecodeError, IndexError):
        fetched = {"_conn_error": (out or err)[-300:]}
    if "_conn_error" in fetched:
        problems.append("IMAP fetch 探针故障：%s" % fetched["_conn_error"])
    queries = []
    for case in accepted:
        rec = fetched.get(case) or {}
        row = rows.setdefault(case, {})
        if rec.get("uid"):
            row["uid"] = rec["uid"]
            row["locator"] = rec.get("locator")
        if rec.get("error"):
            row["error"] = rec["error"]
        if not rec.get("uid"):
            row["error"] = row.get("error") or "not-found-in-inbox"
            problems.append("%s: Dovecot INBOX 未检索到（HEADER 与 TEXT 定位都空）" % case)
            continue
        env_parts = [base64.b64decode(p) for p in rec.get("envelope_parts") or []]
        body_parts = [base64.b64decode(p) for p in rec.get("body_parts") or []]
        raw = _body_from_parts(body_parts)
        (imap_dir / ("%s.stored.raw" % case)).write_bytes(raw)
        env = _envelope_from_slot(env_parts)
        (imap_dir / ("%s.envelope.json" % case)).write_text(
            json.dumps(env, ensure_ascii=False, indent=1), encoding="utf-8")
        header_first = _first_from_value(raw)
        env_addr = env.get("from_slot")
        hdr_addr = _addr_from_value(header_first)
        row["envelope_from"] = env_addr
        row["header_from_first"] = hdr_addr
        row["header_from_raw"] = header_first
        row["envelope_detail"] = env
        row["stored_sha256"] = hashlib.sha256(raw).hexdigest()
        if env_addr:
            queries.append(["%s|env" % case, base64.b64encode(
                env_addr.encode("utf-8")).decode()])
        if hdr_addr:
            queries.append(["%s|hdr" % case, base64.b64encode(
                hdr_addr.encode("utf-8")).decode()])
    # 探针二：SEARCH HEADER FROM（raw socket + CHARSET UTF-8，w2 模式）。
    if queries:
        code, out, err = diffrun.sh(
            ["docker", "exec", "-i", "msl-client", "python3", "-",
             json.dumps(queries)], timeout=600,
            stdin=_IMAP_PROBE_SEARCH.encode())
        try:
            searched = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        except (json.JSONDecodeError, IndexError):
            searched = {"_conn_error": (out or err)[-300:]}
        if "_conn_error" in searched:
            problems.append("IMAP search 探针故障：%s" % searched["_conn_error"])
        for qid, hits in searched.items():
            if "|" not in qid:
                continue
            case, kind = qid.split("|", 1)
            rows.setdefault(case, {})["search_%s" % kind] = hits
            uid = (rows[case] or {}).get("uid")
            if isinstance(hits, dict):
                hits["self_hit"] = uid in (hits.get("uids") or [])
    for case in selected:
        print(json.dumps({"case": case,
                          "locator": (rows.get(case) or {}).get("locator"),
                          "env": (rows.get(case) or {}).get("envelope_from"),
                          "hdr": (rows.get(case) or {}).get("header_from_first")}),
              flush=True)
    return rows


def phase_stage2(run_id: str, pt: PriorityTable, cap: int = 400) -> dict:
    stage = RUN_ROOT / run_id / "gramfuzz"
    survivors_path = stage / "survivors.json"
    if not survivors_path.exists():
        raise RuntimeError("缺少 %s——先跑 --phase stage1" % survivors_path)
    survivors = json.loads(survivors_path.read_text(encoding="utf-8"))
    index = {i["case"]: i for i in json.loads(
        (stage / "corpus-index.json").read_text(encoding="utf-8"))}
    rows_by_case = {r["case"]: r for r in json.loads(
        (stage / "stage1.json").read_text(encoding="utf-8"))}
    cases = _dedup_and_cap(rows_by_case, survivors, cap)
    problems: list[str] = []

    relay_rows = _relay_arm(run_id, stage, cases, index, problems)
    anchor, sign_rows = _sign_arm(run_id, stage, cases, index, problems)
    imap_rows = _imap_arm(run_id, stage, cases, index, problems)

    rows = []
    for case in cases:
        row = dict(rows_by_case[case])          # stage1 基础字段（含 views）
        row["relay"] = relay_rows[case]
        srow = sign_rows.get(case)
        if srow is not None:
            row["sign"] = srow
            # classify 的 X 用合并视图：文件级 + postfix 路径（跨路径翻转
            # 是 X 的规范实例——sigprobe2 s2 的 dkimpy parse-error→pass）。
            verdicts = dict(srow.get("file") or {})
            pv = ((srow.get("postfix") or {}).get("verdicts")) or {}
            row["verdicts"] = dict(verdicts,
                                   **{"%s@postfix" % k: v for k, v in pv.items()})
        irow = imap_rows.get(case)
        if irow is not None:
            row["imap"] = irow
            for k in ("envelope_from", "header_from_first"):
                if irow.get(k) is not None:
                    row[k] = irow[k]
        row["arm_error"] = bool(
            any(t.get("error") for t in row["relay"].values())
            or (srow or {}).get("error")
            or ((srow or {}).get("postfix") or {}).get("error")
            or (irow or {}).get("error"))
        row["series"] = classify(row)
        rows.append(row)
    (stage / "stage2.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")

    # 反馈：命中 T/X/D → reward；三臂都测了且无新差分 → punish；有仪器错误
    # 的行不动（不把故障记成落空）。
    for row in rows:
        op = row.get("op")
        if not op:
            continue
        if any(s in row["series"] for s in ("T", "X", "D")):
            pt.reward(op)
        elif not row["arm_error"]:
            pt.punish(op)

    series_counts = Counter(tuple(r["series"]) for r in rows)
    relay_stats: dict[str, dict] = {}
    for target in ("postfix", "exim", "osmtpd"):
        ts = [r["relay"][target] for r in rows if target in r.get("relay", {})]
        relay_stats[target] = {
            "sent": len(ts),
            "captured": sum(1 for t in ts if t.get("captured")),
            "smtp_250": sum(1 for t in ts if t.get("smtp_code") == "250"),
            "gen_preserved_true": sum(1 for t in ts if t.get("gen_preserved") is True),
            "gen_preserved_false": sum(1 for t in ts if t.get("gen_preserved") is False),
            "errors": sum(1 for t in ts if "error" in t),
            "attribution_bad": sum(1 for t in ts if t.get("attribution") == "marker-missing"),
        }
    sign_sel = [r for r in rows if r.get("sign")]
    imap_sel = [r for r in rows if r.get("imap")]
    summary = {
        "survivors_in": len(survivors), "after_cap": len(cases),
        "relay": relay_stats,
        "sign": {
            "anchor_file": anchor["file"],
            "anchor_postfix": (anchor.get("postfix") or {}).get("verdicts"),
            "selected": len(sign_sel),
            "file_split": sum(1 for r in sign_sel
                              if len(set((r["sign"].get("file") or {}).values())) > 1),
            "postfix_split": sum(
                1 for r in sign_sel
                if len(set(((r["sign"].get("postfix") or {}).get("verdicts")
                            or {}).values())) > 1),
            "file_x": sum(1 for r in sign_sel if "X" in r["series"]),
        },
        "imap": {
            "selected": len(imap_sel),
            "delivered": sum(1 for r in imap_sel if r.get("imap", {}).get("uid")),
            "locator_body": sum(1 for r in imap_sel
                                if (r.get("imap") or {}).get("locator") == "body"),
            "mismatch": sum(1 for r in imap_sel
                            if r.get("envelope_from") and r.get("header_from_first")
                            and r["envelope_from"] != r["header_from_first"]),
            "search_self_hit_env": sum(
                1 for r in imap_sel
                if ((r.get("imap") or {}).get("search_env") or {}).get("self_hit")),
            "search_self_hit_hdr": sum(
                1 for r in imap_sel
                if ((r.get("imap") or {}).get("search_hdr") or {}).get("self_hit")),
        },
        "series": {"+".join(k): v for k, v in sorted(series_counts.items())},
        "problems": problems,
    }
    (stage / "stage2-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print("stage2: %d rows; series=%s; problems=%d"
          % (len(rows), summary["series"], len(problems)))
    return summary

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="gramfuzz 语法差分漏斗")
    ap.add_argument("run_id", help="如 w4-20261003a")
    ap.add_argument("--phase", required=True,
                    choices=["corpus", "stage1", "stage2", "report"])
    ap.add_argument("--smoke", action="store_true",
                    help="corpus phase 每入口 fresh/mutated 各 %d 条试跑"
                         % SMOKE_PER_KIND)
    ap.add_argument("--per-entry", type=int, default=None, metavar="N",
                    help="试跑规模：每入口 fresh/mutated 各 N 条（覆盖默认 "
                         "%d/%d 与 --smoke；全量 campaign 前的小规模试跑用）"
                         % (FRESH_PER_ENTRY, MUTATED_PER_ENTRY))
    args = ap.parse_args(argv)

    if args.phase == "report":
        print("任务 7 未实现：report 属任务 7（campaign 与 candidates.json）")
        return 2

    stage = RUN_ROOT / args.run_id / "gramfuzz"
    stage.mkdir(parents=True, exist_ok=True)
    if args.phase == "stage2":
        # 权重表与 corpus phase 共用同一份（stage-2 的 reward/punish 落同文件）。
        pt = PriorityTable(stage / "weights.json")
        phase_stage2(args.run_id, pt)
        return 0
    if args.phase == "corpus":
        if args.per_entry is not None:
            fresh = mutated = args.per_entry
        elif args.smoke:
            fresh = mutated = SMOKE_PER_KIND
        else:
            fresh = mutated = None
        pt = PriorityTable(stage / "weights.json")  # 权重表持久化于同目录
        phase_corpus(args.run_id, pt,
                     fresh_per=fresh or FRESH_PER_ENTRY,
                     mutated_per=mutated or MUTATED_PER_ENTRY)
        pt._save()  # 任务 5 只落盘默认表；reward/punish 由任务 6 的 stage-2 累积
    else:
        phase_stage1(args.run_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
