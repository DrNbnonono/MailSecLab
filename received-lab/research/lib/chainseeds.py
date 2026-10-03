"""chainseeds: 链引擎种子注册表——四源统一，字节级复用各源实验的构建器。

四源（对应 GAP5 §三装配表的既有现货）：
  diffrun   8 种 Received 语法形态（N=25）——L1 识别/规范化轴
  sigprobe2 3 种签名基线（h=from:to:subject:date:received）——签名 × obs × 中继轴，
            其中 s2 是已确认的两跳 flip 锚（osmtpd 保留→dkimpy parse-error；
            postfix 规范化→pass）
  repair    11 个单跳性质探针（obs-From/U-label/群组/domain-literal/8-bit 名/
            外域 AR/重复 From/obs 签名）——L2 性质轴；exim 列由链引擎单跳前缀臂补齐
  w1-causal From-above 突变体——实例选择 × 显示层轴（remain.py 用过的同一种子）

每个种子 build(case_id) -> bytes：内嵌 Subject/Message-ID/X-Case-ID 定位三件套。
sink_admitted 标记「过中继后预期头区终结/沉正文」的种子——头区终结正是链差分
的研究对象（v03/v04/rp-bit8-name 的真实头在中继后的命运），不是语料缺陷；
capture 抓取必须带无主题回退（整封 raw 按 X-Case-ID 字节匹配）。

阈值控制信（N=55 的计数组合锚）不是注册表种子——由 build_control() 即时构建。
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib import diffrun, repair_matrix, sigprobe2

MUTANT_PATH = Path(
    "/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/causal/cases/"
    "from-relaxed-n1-h1-insert-before/mutant.eml")

# 定位三件套模板沿用 sigprobe2.build_case 的头布局（银行钓鱼语境，From=lab.test）
_SP2_TAIL = (b"From: Bank Security <security@lab.test>\r\n"
             b"To: bob@lab.test\r\n"
             b"Date: Sat, 3 Oct 2026 22:30:00 +0000\r\n")


@dataclass
class Seed:
    name: str
    build: Callable[[str], bytes]
    source: str
    sink_admitted: bool = False
    known_single_hop: dict = field(default_factory=dict)
    # corpus_check 预期命中的问题模式（显式承认，F1 教训的放行通道）。
    # repair 族正文含 "Case: <id>" 行（w2 原版语料格式），会被自检判为
    # 「正文类头行」——它是 body 文本不是 sink 伪影，不构成拒发理由。
    admits_check: tuple[str, ...] = ()


def _build_diffrun(variant: str) -> Callable[[str], bytes]:
    def build(case_id: str) -> bytes:
        return diffrun.build_raw(diffrun.VARIANTS[variant], 25, case_id)
    return build


def _sp2_case(case_id: str, tpl: str) -> bytes:
    """sigprobe2.build_case 的 case_id 参数化镜像（模板/头布局一致）。"""
    head = "\r\n".join(tpl.format(i=i) for i in range(3)).encode()
    return (head + b"\r\n" + _SP2_TAIL
            + f"Subject: {case_id}\r\n".encode()
            + f"Message-ID: <{case_id}@lab.test>\r\n".encode()
            + f"X-Case-ID: {case_id}\r\n".encode()
            + b"\r\nPlease confirm the payment.\r\n")


def _build_s0(case_id: str) -> bytes:
    return sigprobe2.sign_custom(_sp2_case(case_id, sigprobe2.STRICT))


def _build_s1(case_id: str) -> bytes:
    return sigprobe2.sign_custom(_sp2_case(case_id, sigprobe2.OBS))


def _build_s2(case_id: str) -> bytes:
    signed = sigprobe2.sign_custom(_sp2_case(case_id, sigprobe2.STRICT))
    return sigprobe2.OBS.format(i=9).encode() + b"\r\n" + signed


def _build_repair(probe: str) -> Callable[[str], bytes]:
    def build(case_id: str) -> bytes:
        return repair_matrix.build_probe(probe, case_id)
    return build


def _build_mutant(case_id: str) -> bytes:
    """w1 From-above 突变体 + 顶部新 X-Case-ID（remain.py prepare() 同款，
    X-Case-ID 不在 h= 内，签名字节与突变语义不变）。"""
    return b"X-Case-ID: " + case_id.encode() + b"\r\n" + MUTANT_PATH.read_bytes()


def build_control(variant: str, n: int, case_id: str) -> bytes:
    """阈值控制信（diffrun 形态 × 任意 N）。"""
    return diffrun.build_raw(diffrun.VARIANTS[variant], n, case_id)


SEEDS: dict[str, Seed] = {}

# ---- 源 1：diffrun 8 形态（N=25；阈值事实见 w3 diffrun RECORD 判决表）----
for _variant in diffrun.VARIANTS:
    _sink = _variant in ("v03-nocolon", "v04-8bit-name")
    SEEDS[_variant] = Seed(
        _variant, _build_diffrun(_variant), "diffrun", sink_admitted=_sink,
        known_single_hop={
            "threshold_n55": {"postfix": "554", "exim": "bounce", "osmtpd": "deliver"},
        })

# v01/v07 的字节级单跳锚（w3 diffrun 捕获臂）
SEEDS["v01-obs-colon"].known_single_hop.update({
    "postfix": {"normalized": True},      # obs→strict 改写，strict=26
    "osmtpd": {"preserved": True},        # obs=25 保留 + strict=1（自产）
})
SEEDS["v07-tab-name"].known_single_hop.update({
    "postfix": {"normalized": True},
    "osmtpd": {"preserved": True},
})

# ---- 源 2：sigprobe2 3 签名基线（w3 sigprobe2 matrix.json 九格）----
SEEDS["s0-strict-signed"] = Seed(
    "s0-strict-signed", _build_s0, "sigprobe2",
    known_single_hop={"norelay": {"dkimpy": "pass", "perl": "pass", "go": "pass", "rspamd": "pass"},
                      "postfix": {"dkimpy": "pass", "perl": "pass", "go": "pass", "rspamd": "pass"},
                      "osmtpd": {"dkimpy": "pass", "perl": "pass", "go": "pass", "rspamd": "pass"}})
SEEDS["s1-obs-signed"] = Seed(
    "s1-obs-signed", _build_s1, "sigprobe2",
    known_single_hop={"norelay": {"dkimpy": "parse-error", "perl": "fail", "go": "fail", "rspamd": "fail"},
                      "postfix": {"dkimpy": "fail", "perl": "fail", "go": "fail", "rspamd": "fail"},
                      "osmtpd": {"dkimpy": "parse-error", "perl": "fail", "go": "fail", "rspamd": "fail"}})
SEEDS["s2-obs-injected"] = Seed(
    "s2-obs-injected", _build_s2, "sigprobe2",
    known_single_hop={"norelay": {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"},
                      "postfix": {"dkimpy": "pass", "perl": "pass", "go": "pass", "rspamd": "pass"},
                      "osmtpd": {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"}})

# ---- 源 3：repair 11 探针（w2 repair matrix；exim 列待链引擎补）----
for _probe in repair_matrix.PROBES:
    SEEDS[f"rp-{_probe}"] = Seed(
        f"rp-{_probe}", _build_repair(_probe), "repair",
        sink_admitted=_probe == "bit8-name",
        admits_check=("header-like line(s) in the body",))

# ---- 源 4：w1 causal From-above 突变体 ----
SEEDS["w1-from-above-mutant"] = Seed(
    "w1-from-above-mutant", _build_mutant, "w1-causal",
    known_single_hop={"norelay": {"dkimpy": "fail", "perl": "pass", "go": "pass", "rspamd": "fail"},
                      "postfix3hops": {"delivered": True, "perl": "pass", "go": "pass"}},
    admits_check=("header-like line(s) in the body",))  # 正文 "Case: <id>" 行，w1 原版格式
