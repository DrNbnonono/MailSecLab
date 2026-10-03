"""机制家族聚类：stage2 行 → 家族（MIMEminer 的方法类折叠）。

MIMEminer 的 19 条是聚类结果不是原始命中数——本模块做同样的折叠：
同族 = 同一机制在不同种子/字节上的重现。representative 取首例，
members 全留（证据链不丢）。

三级键（w4 实测校准，见 families*.json 的 lineage）：

- fine：计划原键 (entry, op, views 全元组, 保留形态, 判定形态)。w4 实测
  236 行全为单例——field_count 逐字节变化，噪声主导。
- mid：计划粗化（views 的 field_count 降级为参考字段）。w4 实测 186 族，
  仍远超 60，计划的唯一粗化步在真实数据上不够。
- mech：机制级键 (入口类, 算子类, P 差分特征, 中继保留三元组, X 判定形态,
  D 形态)。field_count 的差分折叠为「谁的字段数最低」的 argmin 模式
  （python 最低 = P4 的头区提前终结机制），received_count 折叠为
  「是否计到 0」，算子按 obs 冒号/折行/字节/行/原生归类，入口按
  身份/trace/AR/DKIM 归类。mech 是 A2 最小化与 A3 符合性判定的操作键。

三级都落盘：families-fine.json / families-mid.json / families-mech.json，
families.json = mech 版（操作版）并记录三级谱系。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PARSERS = ("python", "go", "node")

# 算子 → 机制类（E3/w4 RECORD：space/tab-colon 同为 obs 冒号注入）。
OP_CLASS = {
    None: "fresh",
    "guided.space-colon": "obs-colon", "guided.tab-colon": "obs-colon",
    "guided.fold-line": "fold",
    "byte.flip": "byte", "byte.insert": "byte", "byte.delete": "byte",
    "line.del": "line", "line.move": "line", "line.dup": "line",
    "guided.dup-line": "line", "guided.case-name": "case-name",
}

# 入口 → 条款域类（A3 的 RFC 条款映射按代表案例的原始 entry 做，
# 类只用于聚族：身份头 / trace / AR / DKIM）。
ENTRY_CLASS = {
    "from": "identity", "obs-from": "identity", "sender": "identity",
    "reply-to": "identity", "return-path": "identity", "resent-from": "identity",
    "received": "trace", "obs-received": "trace",
    "authres": "ar", "arc-aar": "ar", "arc-ams": "ar", "arc-as": "ar",
    "dkim-tags": "dkim",
}


def _norm_view(v) -> tuple | None:
    """stage2 的 views 值（JSON 往返后是 list）→ 可哈希 tuple；error 视为 ('error',)。"""
    if isinstance(v, (list, tuple)) and len(v) == 3:
        return (v[0], v[1], v[2])
    return ("error",)


def _shape(views: dict) -> tuple:
    return tuple(sorted((k, _norm_view(v)) for k, v in (views or {}).items()))


def _shape_mid(views: dict) -> tuple:
    # field_count 降级：只留 (received_count, from_in_headers) 与 error 形态。
    out = []
    for k, v in sorted((views or {}).items()):
        t = _norm_view(v)
        out.append((k, t if t == ("error",) else (t[0], t[1])))
    return tuple(out)


def _pdiff(views: dict) -> tuple:
    """P 差分特征：三家在哪一层不一致（机制语义，与字节深度无关）。

    - err-python/go/node：该 parser 整体报错
    - fb：from_in_headers 分歧（From 可见性翻转）
    - rc0：received_count 是否计到 0 的分歧（E3「计入 vs 不计」）
    - fc-min=p / fc-other：field_count 分歧的最小值归属
      （python 最低且其余同值 = P4 头区提前终结的标准形态）
    """
    t = {k: _norm_view((views or {}).get(k)) for k in PARSERS}
    feats = []
    for k in PARSERS:
        if t[k] == ("error",):
            feats.append("err-" + k[0])
    oks = {k: v for k, v in t.items() if v != ("error",)}
    if oks and len({bool(v[1]) for v in oks.values()}) > 1:
        feats.append("fb")
    if oks and len({v[0] > 0 for v in oks.values()}) > 1:
        feats.append("rc0")
    if len(oks) == 3 and len({v[2] for v in oks.values()}) > 1:
        mn = min(t[k][2] for k in PARSERS)
        who = "+".join(k[0] for k in PARSERS if t[k][2] == mn)
        feats.append("fc-min=p" if who == "p" else "fc-min=" + who)
    return tuple(sorted(feats))


def _preserved(relay: dict) -> tuple:
    return tuple(sorted((t, (r or {}).get("gen_preserved"))
                        for t, r in (relay or {}).items()))


def _vshape(verdicts: dict) -> tuple:
    return tuple(sorted((k, v) for k, v in (verdicts or {}).items()))


def _dshape(row: dict) -> str | None:
    imap = row.get("imap") or {}
    env = imap.get("envelope_from") or ""
    if not imap:
        return None
    if "missing_mailbox@missing_domain" in env:
        return "placeholder"
    if "@syntax_error" in env:
        return "syntax_error"
    return "other"


def family_key(row: dict, level: str = "fine") -> tuple:
    if level == "fine":
        return (row.get("entry"), row.get("op"), _shape(row.get("views")),
                _preserved(row.get("relay")), _vshape(row.get("verdicts")))
    if level == "mid":
        return (row.get("entry"), row.get("op"), _shape_mid(row.get("views")),
                _preserved(row.get("relay")), _vshape(row.get("verdicts")))
    if level == "mech":
        return (ENTRY_CLASS.get(row.get("entry"), row.get("entry")),
                OP_CLASS.get(row.get("op"), row.get("op")),
                _pdiff(row.get("views")), _preserved(row.get("relay")),
                _vshape(row.get("verdicts")), _dshape(row))
    raise ValueError("unknown level %r (fine|mid|mech)" % level)


def _jsonable(key: tuple) -> list:
    out = []
    for part in key:
        if isinstance(part, tuple):
            out.append([list(p) if isinstance(p, tuple) else p for p in part])
        else:
            out.append(part)
    return out


def cluster_rows(rows: list[dict], level: str = "fine") -> list[dict]:
    fams: dict[tuple, dict] = {}
    for row in rows:
        key = family_key(row, level)
        fam = fams.get(key)
        if fam is None:
            fam = fams[key] = {
                "level": level, "key": _jsonable(key),
                "representative": row["case"], "members": [], "n": 0,
                "series_union": set(),
            }
        fam["members"].append(row["case"])
        fam["n"] += 1
        fam["series_union"].update(row.get("series") or [])
    for fam in fams.values():
        fam["series_union"] = sorted(fam["series_union"])
    return sorted(fams.values(), key=lambda f: (-f["n"], f["representative"]))


def _load_rows(run_dir: Path) -> list[dict]:
    stage2 = json.loads((run_dir / "stage2.json").read_text(encoding="utf-8"))
    return stage2["rows"] if isinstance(stage2, dict) else stage2


def main(run_dir: str, out_dir: str | None = None) -> int:
    run_dir = Path(run_dir)
    rows = _load_rows(run_dir)
    out = Path(out_dir) if out_dir else run_dir.parent / "confirm"
    out.mkdir(parents=True, exist_ok=True)
    counts = {}
    for level, fname in (("fine", "families-fine.json"), ("mid", "families-mid.json"),
                         ("mech", "families-mech.json")):
        fams = cluster_rows(rows, level)
        counts[level] = len(fams)
        (out / fname).write_text(
            json.dumps({"level": level, "n_families": len(fams), "n_rows": len(rows),
                        "families": fams}, ensure_ascii=False, indent=1),
            encoding="utf-8")
    fams = cluster_rows(rows, "mech")
    doc = {
        "level": "mech",
        "operative": True,
        "lineage": {
            "fine": {"n_families": counts["fine"],
                     "note": "计划原键；w4 实测全单例（field_count 字节噪声）"},
            "mid": {"n_families": counts["mid"],
                    "note": "计划粗化（field_count 降级）；仍 >60，噪声在 rc/fc 深度"},
            "mech": {"n_families": counts["mech"],
                     "note": "机制级操作键：入口类×算子类×P 差分特征×保留三元组×X 形态×D 形态"},
        },
        "n_rows": len(rows),
        "n_families": counts["mech"],
        "families": fams,
    }
    (out / "families.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("rows=%d families fine/mid/mech = %d/%d/%d" %
          (len(rows), counts["fine"], counts["mid"], counts["mech"]))
    print("top:", [(f["key"][0], f["key"][1], f["n"]) for f in fams[:8]])
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
