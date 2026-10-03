"""chainflip: 链矩阵分析层——组合专属 flip、路径依赖、字节非交换性。

三个问题（GAP2 §四.3 的操作化）：
  flip（语义不可传递）  种子 s 的链终态判决叶 ∉ {norelay, 单跳 A, 单跳 B} 的
                        同叶值集合——组合产生了任何单跳都未产生的判决。
  路径依赖              verdicts(A→B) ≠ verdicts(B→A)，同种子同臂。
  字节非交换            facts(A→B) ≠ facts(B→A)——同跳集不同序，字节命运不同。

已知锚（阈值计数探针等设计内效应）标 known=true，不计新发现；
sigprobe2 s2 族的单跳效应（postfix 规范化→pass）在 flip 定义下天然不算
组合 flip——它每个单跳结果都被计入基线集合。

复核：reverify_files 对已投递行按存档重放文件级四验证器（只读，无需栈窗口）；
全量重发复核属于栈窗口任务。
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.chainrun import SEQUENCES_V0

RUN_ROOT = Path("/mnt/e/MailSecLab/received-lab/results/research")

_LEAF_AR_KEYS = ("dkim", "dmarc", "spf", "arc", "header_from", "header_d")


def verdict_signature(row: dict) -> tuple:
    """行的语义投影（可比较、可 JSON 化的单值）。"""
    v = row.get("verdicts") or {}
    ar = v.get("ar") or {}
    return (
        row.get("delivered"),
        (row.get("smtp_code") or " ")[0],
        tuple(sorted((v.get("dkim") or {}).items())),
        ar.get("dkim"), ar.get("dmarc"), ar.get("header_from"),
        v.get("milter_rspamd"),
        (v.get("envelope") or {}).get("from_first"),
    )


def row_leaves(row: dict) -> dict:
    """判决叶表：delivery 合并 delivered+smtp 首字符为一叶（同一事实的两个面）。"""
    v = row.get("verdicts") or {}
    out: dict = {"delivery": [row.get("delivered"), (row.get("smtp_code") or " ")[0]]}
    for k, val in (v.get("dkim") or {}).items():
        out[f"dkim.{k}"] = val
    ar = v.get("ar") or {}
    for k in _LEAF_AR_KEYS:
        if k in ar:
            out[f"ar.{k}"] = ar[k]
    if v.get("milter_rspamd") not in (None, "not-collected"):
        out["milter_rspamd"] = v["milter_rspamd"]
    env = v.get("envelope") or {}
    if env.get("from_first"):
        out["envelope.from_first"] = env["from_first"]
    return out


def facts_diff(a: dict | None, b: dict | None) -> dict:
    a, b = a or {}, b or {}
    keys = set(a) | set(b)
    return {k: {"a": a.get(k), "b": b.get(k)}
            for k in keys if a.get(k) != b.get(k)}


def _index(rows: list[dict]) -> dict[tuple[str, str, str], dict]:
    return {(r["seed"], r["sequence"], r["arm"]): r for r in rows
            if r.get("sequence")}


def _swap_pairs(sequences: list[str]) -> list[tuple[str, str]]:
    seen, out = set(), []
    for name in sequences:
        if "-" not in name:
            continue
        a, b = name.split("-", 1)
        swap = f"{b}-{a}"
        if swap in sequences and (swap, name) not in seen:
            seen.add((name, swap))
            out.append((name, swap))
    return out


def _canon(value) -> str:
    """叶值的可哈希规范形（list 值如 delivery 用 JSON 串入集合）。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def find_flips(rows: list[dict]) -> list[dict]:
    idx = _index(rows)
    flips = []
    for seed in sorted({r["seed"] for r in rows}):
        for arm in ("capture", "exec"):
            base = idx.get((seed, "norelay", "norelay"))
            if base is None:
                continue
            base_leaves = row_leaves(base)
            for seq_name, kinds in SEQUENCES_V0.items():
                if len(kinds) != 2:
                    continue
                chain = idx.get((seed, seq_name, arm))
                singles = [idx.get((seed, kinds[0], arm)), idx.get((seed, kinds[1], arm))]
                if chain is None or any(s is None for s in singles):
                    continue
                chain_leaves = row_leaves(chain)
                single_leaves = [row_leaves(s) for s in singles]
                for field, value in chain_leaves.items():
                    known_values = {_canon(base_leaves.get(field))} | {
                        _canon(sl.get(field)) for sl in single_leaves}
                    if _canon(value) not in known_values:
                        flips.append({
                            "seed": seed, "sequence": seq_name, "arm": arm,
                            "field": field, "new_value": value,
                            "baseline_values": sorted(
                                json.dumps(v, ensure_ascii=False) for v in known_values),
                            "known": bool(chain.get("threshold_probe")),
                            "evidence": {
                                "chain_stored": chain.get("stored_path"),
                                "chain_sha256": chain.get("input_sha256"),
                                "single_stored": [s.get("stored_path") for s in singles],
                            },
                        })
    return flips


def path_dependence(rows: list[dict]) -> list[dict]:
    idx = _index(rows)
    out = []
    for seed in sorted({r["seed"] for r in rows}):
        for arm in ("capture", "exec"):
            for x, y in _swap_pairs(sorted({r["sequence"] for r in rows})):
                rx, ry = idx.get((seed, x, arm)), idx.get((seed, y, arm))
                if rx is None or ry is None:
                    continue
                lx, ly = row_leaves(rx), row_leaves(ry)
                diff = facts_diff(lx, ly)
                if diff:
                    out.append({"seed": seed, "arm": arm, "pair": [x, y],
                                "diff": diff,
                                "evidence": {"x_stored": rx.get("stored_path"),
                                             "y_stored": ry.get("stored_path")}})
    return out


def noncommutative_bytes(rows: list[dict]) -> list[dict]:
    idx = _index(rows)
    out = []
    for seed in sorted({r["seed"] for r in rows}):
        for arm in ("capture", "exec"):
            for x, y in _swap_pairs(sorted({r["sequence"] for r in rows})):
                rx, ry = idx.get((seed, x, arm)), idx.get((seed, y, arm))
                if rx is None or ry is None:
                    continue
                diff = facts_diff(rx.get("facts"), ry.get("facts"))
                if diff:
                    out.append({"seed": seed, "arm": arm, "pair": [x, y],
                                "diff": diff,
                                "evidence": {"x_stored": rx.get("stored_path"),
                                             "y_stored": ry.get("stored_path")}})
    return out


def reverify_files(run_id: str, rows: list[dict], frac: float = 0.2,
                   seed: int = 20261003) -> list[dict]:
    """抽样复核：对已投递行的存档重放文件级四验证器，比对运行期记录。

    只读操作（msl-verifiers/msl-rspamd 文件扫描），无需栈独占窗口。
    """
    from research.lib import verdicts

    delivered = [r for r in rows
                 if r.get("delivered") and r.get("stored_path", "").endswith(".eml")]
    rng = random.Random(seed)
    sample = rng.sample(delivered, max(1, int(len(delivered) * frac))) if delivered else []
    mismatches = []
    for row in sample:
        ev_path = f"/evidence/{run_id}/chain/{row['stored_path']}"
        got = verdicts.file_verdicts(ev_path)
        want = (row.get("verdicts") or {}).get("dkim")
        if got != want:
            mismatches.append({"seed": row["seed"], "sequence": row["sequence"],
                               "arm": row["arm"], "recorded": want, "replayed": got})
    return mismatches


def main(run_id: str) -> dict:
    stage = RUN_ROOT / run_id / "chain"
    rows = json.loads((stage / "matrix.json").read_text(encoding="utf-8"))["rows"]
    flips = find_flips(rows)
    report = {
        "counts": {"rows": len(rows),
                   "flips": len(flips),
                   "flips_unknown": sum(1 for f in flips if not f["known"]),
                   "path_dependence": 0, "noncommutative": 0},
        "flips": flips,
        "path_dependence": path_dependence(rows),
        "noncommutative": noncommutative_bytes(rows),
    }
    report["counts"]["path_dependence"] = len(report["path_dependence"])
    report["counts"]["noncommutative"] = len(report["noncommutative"])
    mismatches = []
    try:
        mismatches = reverify_files(run_id, rows)
    except Exception as exc:  # 复核失败不阻塞分析产出，照实记录
        mismatches = [{"error": str(exc)}]
    report["reverify_mismatches"] = mismatches
    (stage / "candidates.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(report["counts"], ensure_ascii=False))
    if mismatches:
        print("reverify mismatches:", len(mismatches))
    return report


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "w6-20261003a")
