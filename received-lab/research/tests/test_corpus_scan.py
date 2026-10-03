"""corpus_scan 单测。合成语料锚定特征计数：obs 形态、重复字段、外域 AR、
domain-literal、by≠from 不一致、超长行、8-bit 头区字节；mbox 切分。"""
import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.corpus_scan import iter_mbox_messages, scan_corpus_dir, scan_message

CLEAN = (
    b"Received: from mx.a.example (mx.a.example [192.0.2.1]) by mx.b.example\r\n"
    b"\twith ESMTP id 1; Sat, 3 Oct 2026 10:00:00 +0000\r\n"
    b"From: Bank <security@a.example>\r\n"
    b"To: bob@b.example\r\nSubject: hello\r\n\r\nbody\r\n"
)


def test_clean_message_has_no_features():
    f = scan_message(CLEAN)
    assert f["obs_received"] == 0
    assert f["dup_from"] == 0
    assert f["foreign_ar"] == 0
    assert f["by_from_mismatch"] == 0
    assert f["header_8bit_bytes"] == 0
    assert f["overlong_lines"] == 0


def test_obs_and_eightbit_and_nocolon_counted():
    raw = (b"Received : from a by b; Sat, 3 Oct 2026 10:00:00 +0000\r\n"
           b"Rece\xedved: from a by b; Sat, 3 Oct 2026 10:01:00 +0000\r\n"
           b"Received from a by b\r\n"
           b"From: x@a.example\r\nSubject: s\r\n\r\nbody\r\n")
    f = scan_message(raw)
    assert f["obs_received"] == 1
    assert f["eightbit_name"] == 1
    assert f["nocolon_received"] == 1


def test_duplicate_fields_counted():
    raw = (b"From: attacker@evil.example\r\n"
           b"From: Bank <security@a.example>\r\n"
           b"Authentication-Results: mx.b.example; dkim=pass\r\n"
           b"Authentication-Results: other.example; dkim=pass\r\n"
           b"To: bob@b.example\r\nSubject: s\r\n\r\nbody\r\n")
    f = scan_message(raw)
    assert f["dup_from"] == 1
    assert f["dup_authentication_results"] == 1


def test_domain_literal_and_long_line():
    long_val = b"x" * 1005
    raw = (b"From: Bank <security@[203.0.113.7]>\r\n"
           + b"X-Long: " + long_val + b"\r\n"
           + b"To: bob@b.example\r\nSubject: s\r\n\r\nbody\r\n")
    f = scan_message(raw)
    assert f["domain_literal_from"] == 1
    assert f["overlong_lines"] == 1


def test_by_from_mismatch_detected():
    # 第二条 Received 的 from-clause 与第一条的 by-clause 不一致（i2 自洽性检测法）
    raw = (b"Received: from mx.a.example by mx.b.example; Sat, 3 Oct 2026 10:00:00 +0000\r\n"
           b"Received: from forged.example by mx.a.example; Sat, 3 Oct 2026 10:01:00 +0000\r\n"
           b"From: x@a.example\r\nSubject: s\r\n\r\nbody\r\n")
    f = scan_message(raw)
    assert f["by_from_mismatch"] == 1


def test_iter_mbox_messages_splits_on_from_lines():
    mbox = (b"From bounce@a.example Sat Oct  3 10:00:00 2026\r\n" + CLEAN +
            b"From bounce@c.example Sat Oct  3 11:00:00 2026\r\n" + CLEAN)
    msgs = list(iter_mbox_messages(mbox))
    assert len(msgs) == 2
    assert msgs[0].startswith(b"Received: from mx.a.example")


def test_scan_corpus_dir_aggregates(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.eml").write_bytes(CLEAN)
    (d / "b.eml").write_bytes(
        b"Received : from a by b; Sat, 3 Oct 2026 10:00:00 +0000\r\n"
        b"From: x@a.example\r\nSubject: s\r\n\r\nbody\r\n")
    (d / "list.mbox").write_bytes(
        b"From bounce@a.example Sat Oct  3 10:00:00 2026\r\n" + CLEAN)
    report = scan_corpus_dir(d)
    assert report["messages"] == 3
    assert report["features"]["obs_received"] == 1
    assert report["rate"]["obs_received"] == 1 / 3
