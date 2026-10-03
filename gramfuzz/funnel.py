"""语法差分漏斗：corpus → stage1（本地三 parser 批量差分）→ stage2（中继/签名/消费）→ report。

    python3 -m gramfuzz.funnel <run_id> --phase corpus [--smoke | --per-entry N]
    python3 -m gramfuzz.funnel <run_id> --phase stage1
    python3 -m gramfuzz.funnel <run_id> --phase stage2   # 任务 6 未实现
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
import hashlib
import json
import random
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
from gramfuzz.lab import (GRAMMAR_DIR, PARSERS_DIR, RFC_DIR, RUN_ROOT,
                          TARGETS_JSON, corpus_check, diffrun)

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


# ---- CLI ----

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

    if args.phase in ("stage2", "report"):
        print("任务 %s 未实现：stage2 属任务 6（三臂接线），report 属任务 7"
              "（campaign 与 candidates.json）" % ("6" if args.phase == "stage2" else "7"))
        return 2

    stage = RUN_ROOT / args.run_id / "gramfuzz"
    stage.mkdir(parents=True, exist_ok=True)
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
