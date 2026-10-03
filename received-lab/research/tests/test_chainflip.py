"""chainflip 单测。合成行验证三类分析：组合专属 flip、路径依赖、字节非交换；
阈值探针按已知设计标注不计新发现。"""
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.chainflip import (
    facts_diff,
    find_flips,
    noncommutative_bytes,
    path_dependence,
    verdict_signature,
)


def _row(seed, sequence, arm, delivered=True, code="250", dkim=None,
         facts=None, threshold=None):
    return {
        "seed": seed, "sequence": sequence, "arm": arm,
        "smtp_code": code, "delivered": delivered,
        "facts": facts or {"received": {"strict": 3}, "received_zone_total": 3},
        "verdicts": {"dkim": dkim or {"dkimpy": "pass", "perl": "pass",
                                      "go": "pass", "rspamd_file": "pass"},
                     "ar": {}, "milter_rspamd": "not-collected",
                     "envelope": {}, "chain": {}, "events": []},
        **({"threshold_probe": threshold} if threshold else {}),
    }


def test_verdict_signature_distinguishes_dkim_and_delivery():
    a = _row("s", "pf", "capture")
    b = _row("s", "pf", "capture", dkim={"dkimpy": "parse-error", "perl": "pass",
                                         "go": "pass", "rspamd_file": "pass"})
    c = _row("s", "pf", "capture", delivered=False, code="554")
    assert verdict_signature(a) != verdict_signature(b)
    assert verdict_signature(a) != verdict_signature(c)


def test_find_flips_detects_composition_specific_change():
    rows = [
        _row("s", "norelay", "norelay"),
        _row("s", "pf", "capture"),
        _row("s", "ex", "capture"),
        # 链终态 dkimpy=parse-error——两个单跳都没有过的判决 → 组合专属 flip
        _row("s", "pf-ex", "capture",
             dkim={"dkimpy": "parse-error", "perl": "pass",
                   "go": "pass", "rspamd_file": "pass"}),
    ]
    flips = find_flips(rows)
    assert len(flips) == 1
    f = flips[0]
    assert f["seed"] == "s" and f["sequence"] == "pf-ex" and f["arm"] == "capture"
    assert f["field"] == "dkim.dkimpy"
    assert f["new_value"] == "parse-error"
    assert f["known"] is False


def test_find_flips_ignores_chain_matching_a_single_hop():
    rows = [
        _row("s", "norelay", "norelay"),
        _row("s", "pf", "capture"),
        _row("s", "ex", "capture", dkim={"dkimpy": "fail", "perl": "pass",
                                         "go": "pass", "rspamd_file": "pass"}),
        # 链终态与单跳 ex 相同 → 单跳效应，不是组合 flip
        _row("s", "pf-ex", "capture", dkim={"dkimpy": "fail", "perl": "pass",
                                            "go": "pass", "rspamd_file": "pass"}),
    ]
    assert find_flips(rows) == []


def test_threshold_probes_are_known_by_design():
    # v00 N=49：单跳 pf 投递、pf-pf 第二跳 554——设计内的计数组合效应
    rows = [
        _row("thr-v00-plain-n49", "norelay", "norelay"),
        _row("thr-v00-plain-n49", "pf", "capture"),
        _row("thr-v00-plain-n49", "ex", "capture"),
        _row("thr-v00-plain-n49", "pf-pf", "capture", delivered=False,
             code="554", threshold="v00-plain/n=49"),
    ]
    flips = find_flips(rows)
    assert len(flips) == 1 and flips[0]["known"] is True


def test_path_dependence_pair():
    rows = [
        _row("s", "pf-ex", "capture"),
        _row("s", "ex-pf", "capture", delivered=False, code="554"),
    ]
    deps = path_dependence(rows)
    assert len(deps) == 1
    # swap pair 按字典序排列（实现稳定序）
    assert tuple(deps[0]["pair"]) == ("ex-pf", "pf-ex")


def test_noncommutative_bytes_diffs_facts():
    rows = [
        _row("s", "pf-ex", "capture",
             facts={"received": {"strict": 27}, "received_zone_total": 27}),
        _row("s", "ex-pf", "capture",
             facts={"received": {"strict": 26, "obs-colon": 1},
                    "received_zone_total": 27}),
    ]
    nc = noncommutative_bytes(rows)
    assert len(nc) == 1
    assert "received" in nc[0]["diff"]


def test_facts_diff_shape():
    d = facts_diff({"received": {"strict": 3}, "zone_end": 10},
                   {"received": {"strict": 4}, "zone_end": 10})
    assert d == {"received": {"a": {"strict": 3}, "b": {"strict": 4}}}
