"""chainseeds 单测。锚定四源字节对齐：diffrun 形态逐字节等于 diffrun.build_raw、
sigprobe2 基线结构复刻（h= 含 received 的签名）、repair 探针、w1 From-above 突变体。
全部种子必须过 corpus_check——头区终结是中继侧行为，语料本身结构完好。"""
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

import pytest

from research.lib.chainseeds import SEEDS, Seed, build_control
from research.lib.tracefacts import corpus_check, facts

MUTANT = Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml")

EXPECTED = [
    # diffrun 8 形态
    "v00-plain", "v01-obs-colon", "v02-case", "v03-nocolon",
    "v04-8bit-name", "v05-cfws-name", "v06-comment-name", "v07-tab-name",
    # sigprobe2 3 签名基线
    "s0-strict-signed", "s1-obs-signed", "s2-obs-injected",
    # repair 11 探针
    "rp-ctl", "rp-ctl-signed", "rp-obs-top", "rp-obs-mid", "rp-ulabel",
    "rp-group", "rp-dl", "rp-bit8-name", "rp-ar-foreign", "rp-dup-from",
    "rp-signed-obs",
    # w1 causal
    "w1-from-above-mutant",
]


def test_registry_complete_and_unique():
    assert sorted(SEEDS) == sorted(EXPECTED)
    assert len(SEEDS) == 23


def test_every_seed_builds_with_case_id_and_clean_corpus():
    for name, seed in SEEDS.items():
        raw = seed.build(f"cs-{name}")
        assert b"X-Case-ID: cs-" + name.encode() in raw, name
        problems = corpus_check(raw)
        admitted = [p for p in problems
                    if any(pat in p for pat in seed.admits_check)]
        unexpected = [p for p in problems if p not in admitted]
        assert unexpected == [], f"{name}: {unexpected}"


def test_sink_admitted_marks_zone_termination_family():
    assert SEEDS["v03-nocolon"].sink_admitted
    assert SEEDS["v04-8bit-name"].sink_admitted
    assert SEEDS["rp-bit8-name"].sink_admitted
    assert not SEEDS["v00-plain"].sink_admitted


def test_diffrun_seeds_are_byte_identical_to_diffrun():
    from research.lib import diffrun
    for variant in ("v00-plain", "v01-obs-colon", "v07-tab-name"):
        got = SEEDS[variant].build(f"cs-{variant}")
        want = diffrun.build_raw(diffrun.VARIANTS[variant], 25, f"cs-{variant}")
        assert got == want


def test_sigprobe2_family_shape():
    from research.lib import sigprobe2
    s0 = SEEDS["s0-strict-signed"].build("cs-s0")
    assert b"DKIM-Signature:" in s0
    assert b"h=from:to:subject:date:received" in s0
    assert facts(s0)["received"] == {"strict": 3}
    s1 = SEEDS["s1-obs-signed"].build("cs-s1")
    assert facts(s1)["received"] == {"obs-colon": 3}
    s2 = SEEDS["s2-obs-injected"].build("cs-s2")
    f2 = facts(s2)["received"]
    assert f2 == {"obs-colon": 1, "strict": 3}
    # s2 顶部注入的 obs 行是 O9 模板（与 sigprobe2 的 i=9 一致）
    assert s2.split(b"\r\n", 1)[0] == sigprobe2.OBS.format(i=9).encode()


def test_repair_probe_shapes():
    from research import structure
    dup = SEEDS["rp-dup-from"].build("cs-dup")
    assert structure.inspect(dup)["counts"].get("from") == 2
    arf = SEEDS["rp-ar-foreign"].build("cs-arf")
    assert b"receiver.example" in arf
    assert b"dkim=pass" in arf
    signed = SEEDS["rp-ctl-signed"].build("cs-cs")
    assert b"DKIM-Signature:" in signed


def test_mutant_seed_has_two_froms_and_case_id():
    if not MUTANT.exists():
        pytest.skip("w1 突变体存档不在本机")
    from research import structure
    raw = SEEDS["w1-from-above-mutant"].build("cs-mut")
    assert structure.inspect(raw)["counts"].get("from") == 2
    assert raw.startswith(b"X-Case-ID: cs-mut\r\n")


def test_known_single_hop_anchors_present_for_control_seeds():
    # 链引擎控制锚依赖的已知单跳结论必须有记录（详见 w3 diffrun/sigprobe2 RECORD）
    assert SEEDS["s2-obs-injected"].known_single_hop.get("postfix", {}).get("dkimpy") == "pass"
    assert SEEDS["s2-obs-injected"].known_single_hop.get("osmtpd", {}).get("dkimpy") == "parse-error"
    assert SEEDS["v01-obs-colon"].known_single_hop.get("postfix", {}).get("normalized") is True
    assert SEEDS["v01-obs-colon"].known_single_hop.get("osmtpd", {}).get("preserved") is True


def test_build_control_threshold_variant():
    raw = build_control("v01-obs-colon", 55, "cs-thr")
    f = facts(raw)
    assert f["received"]["obs-colon"] == 55
    assert corpus_check(raw) == []
