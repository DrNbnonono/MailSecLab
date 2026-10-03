#!/usr/bin/env python3
"""任务 7 Step 7.2：candidates 人工抽样复核的机器侧核对。

对分层抽样选出的 candidate 逐例做字节级复核（w3 教训：fetch 竞态与主题
沉没可能造成仪器伪影）：
  1. 输入 sha256 重算对 corpus-index；
  2. T：gen 字节在存档里的存在性逐目标重算 + 中继标记 + X-Case-ID 在场；
  3. X：四验证器对 sign 输入与 postfix 存档重跑，比对 stage2 记录；
  4. D：ENVELOPE 记录与存档头区第一 From 重算比对。

输出 review.json：每例一记录 + review_flag 建议（人最终判定）。
用法: review_sample.py <run_id> [--rate 0.2] [--seed 7]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/Gramfuzz")
sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from gramfuzz.funnel import (RELAY_MARKERS, RUN_ROOT, _addr_from_value,
                             _display_approx, _envelope_from_slot,
                             _first_from_value, _statuses)
from research.lib.causal import verify_file

EV = "/evidence"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--rate", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    stage = RUN_ROOT / args.run_id / "gramfuzz"
    cands = json.loads((stage / "candidates.json").read_text(encoding="utf-8"))
    s2 = {r["case"]: r for r in json.loads(
        (stage / "stage2.json").read_text(encoding="utf-8"))}
    idx = {i["case"]: i for i in json.loads(
        (stage / "corpus-index.json").read_text(encoding="utf-8"))}

    # 分层：按系列链（排序后的 series 元组）分桶，桶内 ≥20% 抽样（至少 1）。
    strata: dict[tuple, list[dict]] = {}
    for c in cands["candidates"]:
        strata.setdefault(tuple(sorted(c["series"])), []).append(c)
    rng = random.Random(args.seed)
    sampled = []
    for key in sorted(strata, key=str):
        bucket = sorted(strata[key], key=lambda c: c["case"])
        n = max(1, int(round(len(bucket) * args.rate)))
        picked = rng.sample(bucket, n)
        print("stratum %s: %d/%d -> %s" % (
            "+".join(key), n, len(bucket), [c["case"] for c in picked]))
        sampled.extend(picked)

    reviews = []
    for c in sampled:
        case = c["case"]
        row = s2[case]
        rec = {"case": case, "series": c["series"], "checks": {}, "issues": []}
        # 1. 输入 sha256
        raw = (stage / "corpus" / ("%s.eml" % case)).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        rec["checks"]["input_sha256"] = (sha == idx[case]["input_sha256"])
        if not rec["checks"]["input_sha256"]:
            rec["issues"].append("input sha256 mismatch")
        gen = bytes.fromhex(idx[case]["gen_bytes"])
        # 2. T：逐目标重算 gen_preserved / 标记 / 定位键
        for target, trow in sorted((row.get("relay") or {}).items()):
            p = stage / "relay" / target / ("%s.stored.raw" % case)
            if not trow.get("captured") or not p.exists():
                continue
            stored = p.read_bytes()
            chk = {"gen_in_stored": gen in stored,
                   "marker": RELAY_MARKERS[target] in stored,
                   "case_id_in_stored": case.encode() in stored}
            rec["checks"]["relay_%s" % target] = chk
            if chk["gen_in_stored"] != trow.get("gen_preserved"):
                rec["issues"].append(
                    "relay %s gen_preserved 记录=%s 重算=%s"
                    % (target, trow.get("gen_preserved"), chk["gen_in_stored"]))
            if not chk["marker"]:
                rec["issues"].append("relay %s 存档缺中继标记" % target)
        # 3. X：验证器重跑（文件级 + postfix 存档）
        sign = row.get("sign") or {}
        if sign:
            sign_case = sign.get("sign_case") or ("%s-sign" % case)
            ev_sign = "%s/%s/gramfuzz/sign" % (EV, args.run_id)
            file_v = _statuses(verify_file("%s/%s.eml" % (ev_sign, sign_case)))
            rec["checks"]["verdicts_file_recheck"] = file_v
            if file_v != (sign.get("file") or {}):
                rec["issues"].append("文件级验证器重跑与记录不一致：%s vs %s"
                                     % (file_v, sign.get("file")))
            sp = stage / "sign" / ("%s.stored.raw" % sign_case)
            if (sign.get("postfix") or {}).get("captured") and sp.exists():
                post_v = _statuses(verify_file("%s/%s.stored.raw" % (ev_sign, sign_case)))
                rec["checks"]["verdicts_postfix_recheck"] = post_v
                if post_v != ((sign.get("postfix") or {}).get("verdicts") or {}):
                    rec["issues"].append("postfix 路径验证器重跑与记录不一致")
                if gen not in sp.read_bytes() and \
                        (sign.get("postfix") or {}).get("gen_preserved") is True:
                    rec["issues"].append("sign postfix gen_preserved 记录与字节不符")
        # 4. D：ENVELOPE 与头区第一 From 重算
        ip = stage / "imap" / ("%s.stored.raw" % case)
        irow = row.get("imap") or {}
        if irow.get("uid") and ip.exists():
            stored = ip.read_bytes()
            env = json.loads((stage / "imap" / ("%s.envelope.json" % case))
                             .read_text(encoding="utf-8"))
            hdr = _addr_from_value(_first_from_value(stored))
            rec["checks"]["d_recheck"] = {
                "envelope_from": env.get("from_slot"),
                "header_from_first_recalc": hdr,
                "recorded_env": row.get("envelope_from"),
                "recorded_hdr": row.get("header_from_first"),
                "display_approx_recalc": _display_approx(env.get("from_slot"), hdr),
            }
            if env.get("from_slot") != row.get("envelope_from"):
                rec["issues"].append("envelope 记录与 envelope.json 不一致")
            if hdr != row.get("header_from_first"):
                rec["issues"].append("头区第一 From 重算与记录不一致")
        rec["review_flag"] = "; ".join(rec["issues"]) or None
        reviews.append(rec)
        print(json.dumps({"case": case, "flag": rec["review_flag"]},
                         ensure_ascii=False))

    flagged = [r for r in reviews if r["review_flag"]]
    out = {"run_id": args.run_id, "rate": args.rate, "seed": args.seed,
           "sampled": len(reviews), "flagged": len(flagged),
           "strata": {"+".join(k): len(v) for k, v in sorted(strata.items())},
           "reviews": reviews}
    (stage / "review.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("review: %d sampled, %d flagged -> %s"
          % (len(reviews), len(flagged), stage / "review.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
