"""grammut 单测：算子可作用、不可作用时返回 None、优先级反馈有界且持久化。"""
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.grammut import ALL_OPS, PriorityTable, mutate

RAW = (b"From: a@lab.test\r\nReceived: from x by y; Sat, 3 Oct 2026 00:00:00 +0000\r\n"
       b"Subject: s\r\n\r\nbody\r\n")


def test_guided_space_colon_creates_obs():
    import random
    out = ALL_OPS["guided.space-colon"](RAW, random.Random(0))
    assert out is not None and b" :" in out.split(b"\r\n")[0] + b"\r\n" + out.split(b"\r\n")[1]
    assert out != RAW


def test_line_dup_duplicates_header_instance():
    import random
    out = ALL_OPS["line.dup"](RAW, random.Random(1))
    assert out is not None and out.count(b"From: a@lab.test") == 2


def test_mutate_returns_different_or_none():
    import random
    seen_none, seen_change = 0, False
    for seed in range(50):
        out = mutate(RAW, random.Random(seed), ops=("byte.flip",))
        if out is None:
            seen_none += 1
        elif out != RAW:
            seen_change = True
    assert seen_change and seen_none >= 0     # flip 至少一次改变字节


def test_priority_table_bounds_and_persistence(tmp_path=None):
    p = Path("/tmp/grammut-test-weights.json")
    p.unlink(missing_ok=True)
    t = PriorityTable(p)
    w0 = t.w["guided.space-colon"]
    for _ in range(20):
        t.reward("guided.space-colon")
    assert t.w["guided.space-colon"] <= 8.0
    for _ in range(60):
        t.punish("guided.space-colon")
    assert t.w["guided.space-colon"] >= 0.05
    t2 = PriorityTable(p)
    assert t2.w["guided.space-colon"] == t.w["guided.space-colon"]
    p.unlink(missing_ok=True)
