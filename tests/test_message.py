import base64
import hashlib

import pytest


def test_body_cannot_inject_headers(analyze_email):
    raw = b"Subject: demo\r\n\r\nReceived: from fake by fake; nonsense\r\nFrom: fake@bad.example\r\n"
    report = analyze_email(raw)
    assert report.route == []
    assert len(report.headers) == 1
    assert report.message.from_addresses == []
    assert base64.b64decode(report.source.header_base64) == b"Subject: demo\r\n"


@pytest.mark.parametrize("line", [b"Received : x", b"Rece\xc3\xadved: x", b"broken without colon"])
def test_parser_boundary_is_preserved(analyze_email, line):
    raw = line + b"\r\nFrom: a@sender.example\r\n\r\n"
    report = analyze_email(raw)
    assert not report.headers[0].recognized
    assert report.message.from_addresses == []
    assert report.source.semantic_boundary_byte == 0
    assert any(f.code == "HEADER_PARSER_DISAGREEMENT" for f in report.warnings)
    assert report.defects


def test_obsolete_received_candidate_count(analyze_email):
    report = analyze_email(b"Received : x\r\nFrom: a@sender.example\r\n\r\n")
    assert report.route_summary.candidate_received_count == 1
    assert report.route_summary.recognized_received_count == 0
    assert report.headers[0].syntax == "obsolete"


@pytest.mark.parametrize("newline", [b"\r\n", b"\n"])
def test_folded_raw_roundtrip_offsets(analyze_email, newline):
    raw = newline.join([b"Subject: folded", b" text", b"X-Test: \xff", b"", b"body"])
    report = analyze_email(raw)
    physical = base64.b64decode(report.source.header_base64)
    assert report.source.input_sha256 == hashlib.sha256(raw).hexdigest()
    assert report.source.header_sha256 == hashlib.sha256(physical).hexdigest()
    assert report.message.subject == "folded text"
    for header in report.headers:
        assert physical[header.start_byte:header.end_byte].decode("utf-8", "replace") == header.raw
    assert report.headers[0].start_line == 1
    assert report.headers[0].end_line == 2
    assert report.headers[1].start_line == 3


def test_repeated_fields_are_not_overwritten(analyze_email):
    report = analyze_email(b"From: A <a@sender.example>\r\nFrom: B <b@sender.example>\r\nSubject: first\r\nSubject: second\r\n\r\n")
    assert [a.address for a in report.message.from_addresses] == ["a@sender.example", "b@sender.example"]
    assert report.message.subject == "first"
    assert len({h.id for h in report.headers}) == 4
    assert len([f for f in report.warnings if f.code == "DUPLICATE_SINGLETON"]) == 2


def test_one_from_with_multiple_mailboxes_is_not_duplicate(analyze_email):
    report = analyze_email("From: a@sender.example, b@sender.example\n")
    assert len(report.message.from_addresses) == 2
    assert not any(f.code == "DUPLICATE_SINGLETON" for f in report.warnings)


def test_encoded_subject_and_header_only(analyze_email, basic_bytes):
    report = analyze_email(basic_bytes.split(b"\r\n\r\n")[0])
    assert report.message.subject == "项目进度"
    assert report.source.has_body_separator is False
    assert len(report.route) == 2


def test_invalid_address_retains_evidence(analyze_email):
    report = analyze_email("From: not-an-address\n")
    assert report.message.from_addresses == []
    assert report.headers[0].value == "not-an-address"
    assert any(d.code == "INVALID_ADDRESS" for d in report.defects)


def test_quoted_local_part_is_accepted(analyze_email):
    report = analyze_email('From: "Space" <"a b"@sender.example>\n')
    assert report.message.from_addresses[0].address == '"a b"@sender.example'
    assert not report.defects


def test_date_comments_preserve_known_time(analyze_email):
    report = analyze_email("Date: Thu, 01 Oct 2026 12:00:00 +0000 (UTC)\n")
    assert report.message.model_dump(mode="json")["date"] == "2026-10-01T12:00:00Z"


@pytest.mark.parametrize("prefix", [b" orphan continuation\n", b"From sender@sender.example Thu Oct 1 12:00:00 2026\n"])
def test_parser_ignored_record_does_not_hide_accepted_fields(analyze_email, prefix):
    report = analyze_email(prefix + b"From: a@sender.example\nSubject: demo\n")
    assert not report.headers[0].recognized
    assert report.headers[1].recognized
    assert report.headers[2].recognized
    assert report.message.from_addresses[0].address == "a@sender.example"
    assert report.message.subject == "demo"
    assert report.source.semantic_boundary_byte == report.source.header_size_bytes


def test_deep_address_comments_do_not_abort_analysis(analyze_email):
    raw = "From: " + "(" * 1500 + "x" + ")" * 1500 + "\nSubject: remains visible\n"
    report = analyze_email(raw)
    assert report.message.subject == "remains visible"
    assert report.message.from_addresses == []
    assert any(d.code == "INVALID_ADDRESS" for d in report.defects)
