"""tracefacts 单测。合成语料锚定分类；recfuzz2 存档锚定计数。"""
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.tracefacts import (
    classify_received_line,
    corpus_check,
    facts,
)

STRICT = b"Received: from h1.lab.test by h2.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
OBS = b"Received : from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
OBS_TAB = b"Received\t: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CASE = b"rEcEiVeD: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CFWS = b"Received(Router): from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
CFWS_INNER = b"Rece(c)ived: from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"
EIGHTBIT = "Rece\u00edved: from a.lab.test by b.lab.test".encode("utf-8")
NOCOLON = b"Received from a.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000"


def build(*received, body=b"Please confirm.\r\n"):
    head = b"\r\n".join([b"From: a@lab.test", b"To: b@lab.test", *received])
    return head + b"\r\n\r\n" + body


def test_line_classes():
    assert classify_received_line(STRICT) == "strict"
    assert classify_received_line(OBS) == "obs-colon"
    assert classify_received_line(OBS_TAB) == "obs-colon"
    assert classify_received_line(CASE) == "case"
    assert classify_received_line(CFWS) == "cfws"
    assert classify_received_line(CFWS_INNER) == "cfws"
    assert classify_received_line(EIGHTBIT) == "eightbit-name"
    assert classify_received_line(NOCOLON) == "no-colon"
    assert classify_received_line(b"X-Other: no") is None
    assert classify_received_line(b" from continuation; line") is None


def test_eightbit_value_is_not_eightbit_name():
    line = "Received: from m\u00fcnchen.lab.test by b.lab.test; Sat, 3 Oct 2026 20:00:00 +0000".encode("utf-8")
    assert classify_received_line(line) == "strict"


def test_obs_stack_counts_like_osmtpd_capture():
    relay = b"Received: from x.lab.test by opensmtpd.lab.test; Sat, 3 Oct 2026 21:00:00 +0000"
    f = facts(build(*([OBS] * 55), relay))
    assert f["received"]["obs-colon"] == 55
    assert f["received"]["strict"] == 1
    assert f["relay_added"] == 1


def test_zone_termination_is_visible():
    raw = (b"From: a@lab.test\r\n" + EIGHTBIT + b"\r\n\r\n"
           + b"To: b@lab.test\r\nSubject: sank\r\nbody\r\n")
    f = facts(raw)
    assert f["received"]["eightbit-name"] == 1
    assert f["body_headerish"] == 2


def test_double_crlf_artifact_is_flagged():
    # F1 教训：折行生成器在已有 CRLF 上再 join，头区在第一行就结束。
    raw = b"Received: a\r\n\r\nReceived: b\r\n\r\nFrom: a@lab.test\r\n\r\nbody\r\n"
    problems = corpus_check(raw)
    assert any("body" in p for p in problems)


def test_lf_corpus_facts():
    raw = b"From: a@lab.test\n" + OBS + b"\n\nbody\n"
    assert facts(raw)["received"]["obs-colon"] == 1


def test_recfuzz2_capture_anchor():
    from pathlib import Path

    import pytest

    p = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a/recfuzz2/v01-obs-colon-osmtpd.stored.raw")
    if not p.exists():
        pytest.skip("recfuzz2 存档不在本机")
    f = facts(p.read_bytes())
    assert f["received"]["obs-colon"] == 55
    assert f["received"]["strict"] == 2
