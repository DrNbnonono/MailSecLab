"""reduce 单测：ddmin 两级缩减（行级半分 + 行内字节级）与 keep 行保护。

锚定已知最小形态：obs-colon From 的差分谓词在只剩 `From :x` + 模板时
仍成立（python email 不认 `From :`，RFC 5322 obs 语法；E/RECORD 既有事实）。
"""
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.reduce import ddmin_header, split_candidate, x_frozen_split, FamState


def _pred(raw: bytes) -> bool:
    # 谓词示例（族签名的单机简化版）：python 认不出 From，而行仍是
    # obs-colon From 字段形态（From + WSP + 冒号）——差分与形态都在。
    # （计划原文只查 b"From" in raw，那会把冒号也缩掉，与计划自己的
    # b"From :" 断言矛盾；此处按真实族谓词的特征语义收紧。）
    import email
    import re
    try:
        m = email.message_from_bytes(raw)
        py_from = m.get("From") is not None
    except Exception:
        py_from = False
    return (py_from is False
            and re.search(rb"^From[ \t]*:", raw, re.MULTILINE) is not None)


def test_ddmin_shrinks_to_essential_bytes():
    raw = (b"From : Bank Security <security@lab.test>\r\n"
           b"To: bob@lab.test\r\nSubject: s\r\n\r\nbody\r\n")
    out = ddmin_header(raw, _pred)
    assert _pred(out) and b"From :" in out
    assert len(out) < len(raw)


def test_ddmin_keeps_template_lines():
    raw = (b"X-Junk: aaaa\r\n"
           b"From : x\r\n"
           b"To: bob@lab.test\r\nSubject: case-1\r\nMessage-ID: <case-1@lab.test>\r\n"
           b"X-Case-ID: case-1\r\n"
           b"X-More: bbbb\r\n"
           b"\r\nbody\r\n")
    out = ddmin_header(raw, _pred)
    assert b"To: bob@lab.test" in out
    assert b"Subject: case-1" in out
    assert b"X-Case-ID: case-1" in out
    assert b"X-Junk" not in out and b"X-More" not in out


def test_ddmin_does_not_touch_body():
    raw = (b"From : x\r\nSubject: s\r\n\r\nPlease confirm the payment.\r\n")
    out = ddmin_header(raw, _pred)
    assert out.endswith(b"\r\n\r\nPlease confirm the payment.\r\n")


def test_ddmin_never_empties_a_header_line():
    # 行内字节缩减不许把头区行清空——那会制造空行=头区提前结束的伪影。
    raw = (b"From : xyz\r\nSubject: s\r\n\r\nbody\r\n")
    out = ddmin_header(raw, _pred)
    zone = out.split(b"\r\n\r\n")[0]
    assert all(line for line in zone.split(b"\r\n") if line != b"")


def test_split_candidate_flags():
    raw = (b"Gen: 1\r\nTo: bob@lab.test\r\nFrom: Bank Security <security@lab.test>\r\n"
           b"Subject: c\r\n\r\nbody\r\n")
    lines, removable = split_candidate(raw)
    assert lines[0] == b"Gen: 1" and removable[0] is True
    assert removable[1] is False and removable[3] is False   # To/Subject keep
    # 模板 From 精确匹配也 keep；被突变过的 From（obs）则可缩
    assert removable[2] is False
    raw2 = raw.replace(b"From: ", b"From\t: ")
    _, removable2 = split_candidate(raw2)
    assert removable2[2] is True


def test_x_frozen_split_protects_signature():
    # s2 注入结构：[gen 行] + DKIM-Signature(已签，可折行) + 模板 + 正文。
    signed = (b"DKIM-Signature: v=1; a=rsa-sha256; d=lab.test;\r\n"
              b" s=cal; h=from:to:subject:date;\r\n"
              b" bh=QUJD; b=SGVsbG8=\r\n")
    raw = (b"Received : x\r\n" + signed +
           b"From: Bank Security <security@lab.test>\r\nTo: bob@lab.test\r\n"
           b"Subject: c\r\n\r\nbody\r\n")
    gen, frozen = x_frozen_split(raw)
    assert gen == b"Received : x\r\n"
    assert frozen.startswith(signed)
    assert b"b=SGVsbG8=" in frozen
    # gen 区里自带的 DKIM-Signature 行不会被误当已签块（取 From 模板前最后一条）
    raw2 = (b"DKIM-Signature: v=9; garbage\r\n" + raw[len(b"Received : x\r\n"):])
    gen2, frozen2 = x_frozen_split(raw2)
    assert gen2 == b"DKIM-Signature: v=9; garbage\r\n"
    assert frozen2.startswith(signed)


def test_ddmin_line_level_removes_whole_blocks():
    # 多行生成块：行级一次砍半，再行内缩
    raw = (b"Fold: aaa\r\n bbb\r\n ccc\r\nSubject: s\r\n\r\nbody\r\n")
    calls = []

    def pred(b):
        calls.append(1)
        return b"bbb" in b          # bbb 行存在即成立

    out = ddmin_header(raw, pred)
    assert b"bbb" in out
    assert b"aaa" not in out and b"ccc" not in out


def test_wave_engine_matches_reference():
    # FamState（wave 驱动）与 ddmin_header（顺序参考实现）对同一谓词收敛到
    # 同一字节串——wave 批处理不改变 ddmin 语义。
    import email
    import re

    def pred(raw):
        m = email.message_from_bytes(raw)
        return (m.get("From") is None
                and re.search(rb"^From[ \t]*:", raw, re.M) is not None)

    for raw in (
        b"From : Bank Security <security@lab.test>\r\nTo: bob@lab.test\r\n"
        b"Subject: s\r\n\r\nbody\r\n",
        b"X-A: 1111\r\nFrom : xy\tpq\r\nX-B: 22\r\nSubject: s\r\n\r\nbody\r\n",
        b"Fold: aaa\r\n bbb\r\nFrom : zz\r\n ccc\r\nSubject: s\r\n\r\nbody\r\n",
    ):
        ref = ddmin_header(raw, pred)
        st = FamState("f", raw, pred, track="p")
        waves = 0
        while not st.done and waves < 500:
            waves += 1
            trials = st.next_trials()
            if not trials:
                break
            results = {}
            for tid, kind, meta, payload in trials:
                results[tid] = pred(st.trial_bytes(kind, meta, payload))
            st.advance(results)
        assert pred(st.candidate()), raw
        assert st.candidate() == ref, (st.candidate(), ref)
