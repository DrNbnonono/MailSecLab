"""abnf 单测：微型内联文法锚定解析器，RFC 5322 锚定规则抽取。"""
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.abnf import ABNFError, Grammar

RFC5322 = Path("/mnt/e/Gramfuzz/rfc/rfc5322.txt")

MINI = """
demo   = "A:" 1*2WSP word CRLF
word   = "x" / "y" / 1*VCHAR
half   = %x41-43            ; A B C
concat = %d97.98.99         ; abc
either = [ "opt" ] "end"
group  = ( "p" / "q" ) "tail"
inc    = "u"
inc    =/ "v"
sens   = %s"CaseLit"         ; RFC 7405 大小写敏感字面量
"""


def test_mini_grammar_rules_and_shapes():
    g = Grammar()
    g.add_text(MINI)
    assert set(g.rules) >= {"demo", "word", "half", "concat", "either", "group", "inc"}
    assert len(g.rules["inc"].alts) == 2                    # =/ 增量合并
    alt = g.rules["demo"].alts[0]
    assert alt[0] == ("lit", "A:")
    assert alt[1][0] == "rep" and alt[1][1] == 1 and alt[1][2] == 2
    assert g.rules["half"].alts[0][0] == ("set", "ABC")     # 范围展开
    # 多段数值终端（%d97.98.99）包成单 alt 的组：组=序列，gramgen 按序派生，
    # 组边界保留重复算子作用于整段终端的语义（计划草稿此处写成扁平序列，二选一取组形式）
    assert g.rules["concat"].alts[0] == [("group", [[("lit", "a"), ("lit", "b"), ("lit", "c")]])]
    assert g.rules["either"].alts[0][0][0] == "rep" and g.rules["either"].alts[0][0][2] == 1
    assert g.rules["group"].alts[0][0] == ("group", [[("lit", "p")], [("lit", "q")]])
    assert g.rules["sens"].alts[0] == [("lit", "CaseLit")]   # RFC 7405 %s


def test_rfc5322_core_rules_present():
    g = Grammar()
    g.add_text(RFC5322.read_text(encoding="utf-8", errors="replace"))
    # received-token 是 RFC 5322 §3.6.7 的真实规则名；计划草稿写的 received-list
    # 在 RFC 文本中不存在（grep 核对后以 RFC 文本为准，不改实现迁就错误名字）
    for name in ("from", "sender", "reply-to", "return", "received",
                 "resent-from", "obs-received", "obs-from", "received-token"):
        assert name in g.rules, name
    assert g.rules["obs-received"], "obs-received 必须有至少一个 alt"


def test_duplicate_rule_names_are_logged_not_merged():
    g = Grammar()
    g.add_text('a = "x"\na = "y"\n')
    assert g.rules["a"].alts == [[("lit", "x")]]
    assert g.conflicts == ["a"]
