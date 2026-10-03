"""gramfuzz stage-2 系列归类单测（任务 6 Step 6.5，计划三用例）。

模块迁出后路径：gramfuzz.funnel（原 research.lib.gramfuzz）。
"""
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")

from gramfuzz.funnel import classify


def test_p_only():
    row = {"views": {"python": (0, False, 8), "go": (0, True, 7), "node": (25, True, 7)}}
    assert classify(row) == ["P"]


def test_t_chain_when_relay_disagrees_on_preservation():
    row = {"views": {"python": (0, True, 8), "go": (0, True, 7), "node": (25, True, 7)},
           "relay": {"postfix": {"captured": True, "gen_preserved": False},
                     "exim": {"captured": True, "gen_preserved": True}}}
    assert classify(row) == ["P", "T"]


def test_u_when_no_signal():
    assert classify({}) == ["U"]
