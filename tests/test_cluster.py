"""cluster 单测：机制家族聚类三级键（fine/mid/mech）的分组语义。

fine = 计划原键（entry×op×views 全元组×保留形态×判定形态）；
mid = 计划粗化（views 的 field_count 降级为参考字段）；
mech = 机制级（入口类×算子类×P 差分特征×中继保留三元组×X 判定形态×D 形态）。
"""
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.cluster import cluster_rows, family_key


def _row(case, entry="obs-from", op="guided.space-colon", views=None, relay=None,
         verdicts=None, imap=None):
    return {
        "case": case, "entry": entry, "op": op,
        "views": views or {"python": [0, False, 0], "go": [0, True, 7],
                           "node": [0, True, 7]},
        "relay": relay or {"postfix": {"gen_preserved": False},
                           "exim": {"gen_preserved": True}},
        "verdicts": verdicts if verdicts is not None else
        {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"},
        "imap": imap,
    }


def test_family_key_groups_same_mechanism():
    rows = [
        _row("a"),
        _row("b"),
    ]
    fams = cluster_rows(rows)
    assert len(fams) == 1 and fams[0]["n"] == 2
    assert fams[0]["representative"] == "a"
    assert fams[0]["members"] == ["a", "b"]


def test_family_key_distinguishes_verdict_shapes():
    a = _row("a", entry="from", op=None,
             views={"python": [0, True, 7], "go": [0, True, 7], "node": [1, True, 7]})
    b = _row("b", entry="from", op=None,
             views={"python": [0, True, 7], "go": [0, True, 7], "node": [1, True, 7]})
    a["verdicts"] = {"dkimpy": "fail", "rspamd": "fail", "perl": "pass", "go": "pass"}
    b["verdicts"] = {"dkimpy": "pass", "rspamd": "pass", "perl": "parse-error", "go": "pass"}
    assert family_key(a) != family_key(b)


def test_fine_splits_field_count():
    # field_count 是字节级噪声：fine 级区分（计划原键语义），mid 级合并。
    a = _row("a", views={"python": [0, True, 5], "go": [0, True, 7], "node": [0, True, 7]})
    b = _row("b", views={"python": [0, True, 6], "go": [0, True, 7], "node": [0, True, 7]})
    assert family_key(a, level="fine") != family_key(b, level="fine")
    assert family_key(a, level="mid") == family_key(b, level="mid")


def test_mech_merges_op_and_entry_classes():
    # space-colon 与 tab-colon 同为 obs 冒号类；身份头入口同类——mech 级合并。
    a = _row("a", entry="sender", op="guided.space-colon")
    b = _row("b", entry="reply-to", op="guided.tab-colon")
    assert family_key(a, level="mech") == family_key(b, level="mech")


def test_mech_keeps_distinct_relay_outcomes():
    a = _row("a", relay={"postfix": {"gen_preserved": False},
                         "exim": {"gen_preserved": True}})
    b = _row("b", relay={"postfix": {"gen_preserved": True},
                         "exim": {"gen_preserved": True}})
    assert family_key(a, level="mech") != family_key(b, level="mech")


def test_mech_distinguishes_parser_disagreement_kinds():
    # python 整区死亡 vs 三家都在但 field_count 分歧，是两个 P 机制。
    a = _row("a", views={"python": [0, False, 0], "go": [0, True, 7], "node": [0, True, 7]})
    b = _row("b", views={"python": [0, True, 5], "go": [0, True, 7], "node": [0, True, 7]})
    assert family_key(a, level="mech") != family_key(b, level="mech")


def test_cluster_rows_sorted_by_size():
    rows = [_row("x"), _row("y"),
            _row("p", entry="received", op="byte.flip"),
            _row("q", entry="received", op="byte.flip"),
            _row("r", entry="received", op="byte.flip")]
    fams = cluster_rows(rows)
    assert [f["n"] for f in fams] == sorted([f["n"] for f in fams], reverse=True)
    assert fams[0]["representative"] == "p"
