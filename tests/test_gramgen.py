"""gramgen 单测：派生可复现、入口前缀锚定、obs 热点可达、组装结构自检。"""
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")
from gramfuzz.abnf import Grammar
from gramfuzz.gramgen import build_message, generate_sample
from gramfuzz.lab import corpus_check

G = Grammar.load_files(["/mnt/e/Gramfuzz/rfc/rfc5322.txt"])


def one(symbol, tries=400):
    for seed in range(tries):
        s = generate_sample(G, symbol, seed)
        if s:
            return s, seed
    return None, None


def test_entries_produce_expected_prefix():
    for symbol, prefix in [("from", "From:"), ("sender", "Sender:"),
                           ("reply-to", "Reply-To:"), ("return", "Return-Path:"),
                           ("resent-from", "Resent-From:"), ("received", "Received:")]:
        s, seed = one(symbol)
        assert s is not None, symbol
        assert s.startswith(prefix), (symbol, s[:40])


def test_obs_received_can_produce_wsp_before_colon():
    seen = [generate_sample(G, "obs-received", seed) for seed in range(600)]
    seen = [s for s in seen if s]
    assert seen, "obs-received 应可派生"
    assert any(s.startswith("Received") and s[len("Received")] in " \t" for s in seen)


def test_derivation_is_reproducible():
    a = generate_sample(G, "from", 1234)
    b = generate_sample(G, "from", 1234)
    assert a == b


def test_build_message_is_structurally_clean():
    s, _ = one("from")
    raw = build_message(s.encode("latin-1"), "gf-test-001")
    assert b"X-Case-ID: gf-test-001" in raw
    assert b"Subject: gf-test-001" in raw
    assert corpus_check(raw) == [], corpus_check(raw)


# 阻塞点修复的端到端验证：8601 的 authserv-id 依赖 RFC 2045 的 value 规则，
# 8617 的 instance/seal-cv-tag 依赖 RFC 7405 的 %s 字面量。任一缺失则对应
# 入口零样本——零样本不是阴性入口，是仪器缺口（任务 3 报告，本测试防回归）。
_ALL_RFCS = ["/mnt/e/Gramfuzz/rfc/rfc%s.txt" % n
             for n in ("5322", "5321", "8601", "6376", "8617", "6532", "2045")]
G_ALL = Grammar.load_files(_ALL_RFCS)


def test_authres_and_arc_entries_derive():
    for symbol, prefix in [("authres-header-field", "Authentication-Results:"),
                           ("arc-authres-header", "ARC-Authentication-Results:"),
                           ("arc-message-signature", "ARC-Message-Signature:"),
                           ("arc-seal", "ARC-Seal:")]:
        got = [generate_sample(G_ALL, symbol, seed) for seed in range(300)]
        got = [s for s in got if s]
        assert got, "%s 应可派生（检查 abnf 对 %%s 字面量与 RFC 2045 value 的支持）" % symbol
        assert got[0].startswith(prefix), (symbol, got[0][:60])
