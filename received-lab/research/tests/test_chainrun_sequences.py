"""chainrun 单测。纯逻辑层：序列注册表、hop 编排计划、corpus 门、控制锚期望。
栈执行（起容器/发送/抓取）不在单测范围——那是运行期按 Gap 1 窗口择机跑的矩阵。"""
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

import pytest

from research.lib.chainrun import (
    ARM_ENDPOINTS,
    SEQUENCES_V0,
    ChainrunError,
    build_hop_plan,
    case_id,
    check_seed_corpus,
    expected_relay_delta,
    known_key,
)
from research.lib.chainseeds import SEEDS


def test_sequences_v0_is_nine_ordered_pairs():
    assert sorted(SEQUENCES_V0) == sorted([
        "pf-ex", "pf-os", "ex-pf", "ex-os", "os-pf", "os-ex",
        "pf-pf", "ex-ex", "os-os"])
    assert SEQUENCES_V0["pf-ex"] == ("pf", "ex")
    assert SEQUENCES_V0["os-os"] == ("os", "os")


def test_case_id_format():
    assert case_id("s2-obs-injected", "pf-os", "capture") == "s2-obs-injected__pf-os__capture"


def test_build_hop_plan_two_hop_capture():
    plan = build_hop_plan(("pf", "ex"), "msl-mailpit", 1025, "pf-ex")
    assert len(plan) == 2
    h1, h2 = plan
    assert h1["kind"] == "pf" and h1["next_host"] == h2["name"] and h1["next_port"] == 25
    assert h2["kind"] == "ex" and h2["next_host"] == "msl-mailpit" and h2["next_port"] == 1025
    # 容器名 msl- 前缀（dockerctl 约束）且含序列名与位置（可追溯）
    for pos, hop in enumerate(plan, 1):
        assert hop["name"].startswith("msl-cr-pf-ex-")
        assert f"-{pos}-" in hop["name"]


def test_build_hop_plan_single_hop_exec():
    plan = build_hop_plan(("os",), "msl-auth-postfix", 25, "os")
    assert len(plan) == 1
    assert plan[0]["next_host"] == "msl-auth-postfix" and plan[0]["next_port"] == 25


def test_arm_endpoints():
    assert ARM_ENDPOINTS["capture"] == ("msl-mailpit", 1025)
    assert ARM_ENDPOINTS["exec"] == ("msl-auth-postfix", 25)


def test_expected_relay_delta():
    # v00 控制信过链后 Received 总数增量：capture 臂 = 跳数（Mailpit 不加 Received）；
    # exec 臂 = 跳数 + 1（msl-auth-postfix 是终点 MTA，自加一条）
    assert expected_relay_delta(2, "capture") == 2
    assert expected_relay_delta(2, "exec") == 3
    assert expected_relay_delta(1, "capture") == 1


def test_check_seed_corpus_blocks_unadmitted_problems():
    raw = b"From: a@lab.test\r\nX-Fold: 1\r\n\r\nTo: looks@like.header\r\nbody\r\n"
    from research.lib.chainseeds import Seed
    from research.lib.tracefacts import corpus_check
    assert corpus_check(raw)  # 自检确实命中（正文类头行）
    seed = Seed("fake", lambda cid: raw, "test")
    with pytest.raises(ChainrunError):
        check_seed_corpus(seed, raw)
    # 显式承认后放行
    seed_ok = Seed("fake", lambda cid: raw, "test",
                   admits_check=("header-like line(s) in the body",))
    check_seed_corpus(seed_ok, raw)  # 不抛


def test_check_seed_corpus_accepts_all_registry_seeds():
    for name, seed in SEEDS.items():
        check_seed_corpus(seed, seed.build(f"chk-{name}"))  # 不抛即通过


def test_known_key_stable():
    row = {"seed": "s", "sequence": "pf-ex", "arm": "capture",
           "smtp_code": "250", "delivered": True,
           "facts": {"received": {"strict": 3}},
           "verdicts": {"dkim": {"dkimpy": "pass"}}}
    k1 = known_key(row)
    assert k1 == known_key(dict(row))
    row2 = dict(row, verdicts={"dkim": {"dkimpy": "fail"}})
    assert known_key(row2) != k1
