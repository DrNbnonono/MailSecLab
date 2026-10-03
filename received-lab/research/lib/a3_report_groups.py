"""A3.Step2 报告级折叠 v3：119 机制族 → 报告组。

v2→v3 的关键更正：中继维度不再用 stage2 的 gen_preserved（其参照物是
**变异前**的 gen_bytes——75/236 例变异打进了生成头，导致大量幻影改写标记
与漏标；见 w5 confirm/INSTRUMENTATION-CORRECTIONS）。v3 以「实际发送的
corpus 文件字节 vs 各中继存档」的 difflib 行差分为准重新分类：

  per-target 真实分类 ∈
    preserved  输入逐字节存活（含合法的前置添加：中继 trace/milter 头）
    rewrite    有输入行被改写/删除（非纯插入）
    rejected   未投递（550 等）

组键（X 判定形态必须分组的纪律不变）：
  (op_fold, p_primary, who_rewrites_true, x_shape)
  osmtpd 拒收与 D 子型为组属性；每族的真实中继分类与改写机制记入组记录。
"""
from __future__ import annotations

import difflib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

CONFIRM = Path("/mnt/e/MailSecLab/received-lab/results/research/w5-20261003a/confirm")
W4 = Path("/mnt/e/MailSecLab/received-lab/results/research/w4-20261003a/gramfuzz")
RFC_DIR = Path("/mnt/e/Gramfuzz/rfc")

OP_FOLD = {"obs-colon": "obs-colon", "fold": "fold",
           "byte": "damage", "line": "damage", "fresh": "fresh", "case-name": "case-name"}
OBS_NAME = re.compile(r'^[\x21-\x7e]+?[ \t]+:')


# ---------------- 真实中继分类（corpus 输入 vs 存档） ----------------

def diff_ops(inp: bytes, st: bytes):
    a = inp.decode("latin1").split("\r\n")
    b = st.decode("latin1").split("\r\n")
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [(t, a[i1:i2], b[j1:j2]) for t, i1, i2, j1, j2 in sm.get_opcodes()
            if t != "equal" and not (t == "insert" and i1 == 0)]


IDENTITY_ENTRIES = {"from", "obs-from", "sender", "reply-to", "resent-from"}


def relay_truth(case: str, entry: str = "") -> dict:
    """对一例三目标：真实分类 + 改写行机制桶（viol/defens 分开）。"""
    inp = (W4 / "corpus" / ("%s.eml" % case)).read_bytes()
    out = {}
    for t in ("postfix", "exim", "osmtpd"):
        p = W4 / "relay" / t / ("%s.stored.raw" % case)
        if not p.exists():
            out[t] = {"class": "no-data"}
            continue
        st = p.read_bytes()
        if inp in st:
            out[t] = {"class": "preserved"}
            continue
        ops = diff_ops(inp, st)
        if not ops:
            out[t] = {"class": "preserved"}
            continue
        mechs = set()
        for tag, al, bl in ops:
            for ln in al:
                if ln.startswith("Return-Path"):
                    mechs.add("return-path-final-delivery")
                elif ln.startswith("From ") and t == "postfix":
                    mechs.add("mbox-lift")
                elif not ln.strip():
                    mechs.add("wsp-line-drop")
                elif OBS_NAME.match(ln) and t == "postfix":
                    mechs.add("obs-colon-normalize")
                elif any(ord(c) < 9 or (13 < ord(c) < 32) for c in ln):
                    mechs.add("bare-CR/control-char-repair")
                elif t == "osmtpd" and (ln.startswith(("From", "To", "Cc", "Sender", "Reply-To"))
                                         or entry in IDENTITY_ENTRIES):
                    # osmtpd 对 From/To/Cc 的域名补全重串行化改的是折行值（首 WSP 行），
                    # 行首不是头名——按入口归属判定（源码机制已核：header_domain_append_callback）
                    mechs.add("domain-append-reserialize")
                else:
                    mechs.add("content-rewrite")
        out[t] = {"class": "rewrite", "mechanisms": sorted(mechs)}
    return out


def p_primary_and_mods(pfeat: list[str]) -> tuple[str, list[str]]:
    feats = set(pfeat)
    mods = []
    if "fb" in feats:
        mods.append("from-flip")
    if "rc0" in feats:
        mods.append("rc0")
    if any(f.startswith("fc-min=p") for f in feats):
        return "py-zone-death", mods
    if any(f.startswith("fc-min=n") for f in feats):
        return "node-zone-death", mods
    if any(f.startswith("fc-min=g") for f in feats):
        return "go-zone-death", mods
    if "err-g" in feats:
        return "go-whole-error", mods
    if mods:
        return "from-flip-only" if "from-flip" in mods else "rc0-only", mods
    return "none", mods


def x_shape(vshape: list) -> str:
    d = {k: v for k, v in vshape}
    if not d or all(v == "pass" for v in d.values()):
        return "none"
    dk = d.get("dkimpy"); dkp = d.get("dkimpy@postfix")
    pl = d.get("perl"); plp = d.get("perl@postfix")
    go = d.get("go"); gop = d.get("go@postfix")
    rs = d.get("rspamd"); rsp = d.get("rspamd@postfix")
    if pl == "parse-error" and dk == "fail" and go == "fail" and rs == "pass":
        return "perl-solo-parse-error"
    if dk == "fail" and rs == "fail" and pl == "pass" and go == "pass":
        return "dkimpy-rspamd-fail"
    if dk == "tool-error" and dkp == "fail" and (plp == "none" or gop == "none" or rsp == "none"):
        return "dkimpy-tool-error-drown"
    if dk == "parse-error" and dkp == "fail" and rsp == "fail" and (pl == "pass" or plp in (None, "pass")):
        return "dkimpy-parse-error-drown"
    return "x-misc:" + ",".join(f"{k}={v}" for k, v in sorted(d.items()) if v != "pass")


def main() -> int:
    rr = json.loads((CONFIRM / "reduce-report.json").read_text(encoding="utf-8"))
    fams = rr["families"]
    s2 = json.loads((W4 / "stage2.json").read_text(encoding="utf-8"))
    rows = s2["rows"] if isinstance(s2, dict) else s2
    bycase = {r["case"]: r for r in rows}

    groups: dict[tuple, dict] = {}
    truth_cache = {}
    for f in fams:
        mk = f["mech_key"]
        op_cls, pfeat, vshape, dshape = mk[1], mk[2], mk[4], mk[5]
        p_prim, p_mods = p_primary_and_mods(pfeat)
        xs = x_shape(vshape)
        case = f["family"]  # representative
        if case not in truth_cache:
            truth_cache[case] = relay_truth(case, f["entry"])
        truth = truth_cache[case]
        who = "+".join(sorted(t[0] for t in ("postfix", "exim", "osmtpd")
                              if truth.get(t, {}).get("class") == "rewrite")) or "none"
        key = (OP_FOLD.get(op_cls, op_cls), p_prim, who, xs)
        g = groups.setdefault(key, {
            "group_key": {"op": key[0], "p_primary": key[1], "who_rewrites_true": key[2],
                          "x_shape": key[3]},
            "families": [], "members_total": 0, "series_union": set(),
            "entries": set(), "ops": set(), "p_mods": set(), "d_subshapes": set(),
            "osmtpd_reject_families": [], "t_ok_families": [], "t_drift_families": [],
            "x_ok_families": [], "relay_truth": {}, "statuses": {},
        })
        g["families"].append(f["family"])
        g["members_total"] += f["n_members"]
        g["series_union"].update(f["series_union"])
        g["entries"].add(f["entry"])
        g["ops"].add(str(f["op"]))
        g["p_mods"].update(p_mods)
        if dshape is not None:
            g["d_subshapes"].add(dshape)
        g["statuses"][f["family"]] = f["status"]
        g["relay_truth"][f["family"]] = truth
        st2 = bycase.get(case, {})
        if (st2.get("relay", {}).get("osmtpd") or {}).get("captured") is False:
            g["osmtpd_reject_families"].append(f["family"])
        if f.get("t_verify") is True:
            g["t_ok_families"].append(f["family"])
        elif "T" in f["series_union"] and f.get("t_verify") is False:
            g["t_drift_families"].append(f["family"])
        if f.get("x_verify") is True:
            g["x_ok_families"].append(f["family"])

    out = []
    for k, g in sorted(groups.items(), key=lambda kv: (-kv[1]["members_total"], str(kv[0]))):
        g["series_union"] = sorted(g["series_union"])
        g["entries"] = sorted(g["entries"])
        g["ops"] = sorted(g["ops"])
        g["p_mods"] = sorted(g["p_mods"])
        g["d_subshapes"] = sorted(g["d_subshapes"])
        g["group_id"] = "G%02d" % (len(out) + 1)
        g["n_families"] = len(g["families"])
        g.pop("statuses")
        out.append(g)
    doc = {"n_groups": len(out), "n_families": len(fams), "groups": out,
           "note": "v3: who_rewrites_true 按实际输入 vs 存档的 difflib 行差分重算（gen_preserved 幻影更正后）"}
    (CONFIRM / "report-groups.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("groups:", len(out), "families:", len(fams))
    for g in out:
        print(f"{g['group_id']} nfam={g['n_families']:3d} memb={g['members_total']:3d} "
              f"{g['group_key']['op']:9s} {g['group_key']['p_primary']:16s} "
              f"rw={g['group_key']['who_rewrites_true']:16s} "
              f"X={g['group_key']['x_shape']:26s} "
              f"{'/'.join(g['series_union']):9s} rej={len(g['osmtpd_reject_families'])} "
              f"D={','.join(g['d_subshapes']) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
