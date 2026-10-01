import pytest


def test_comment_keywords_and_semicolon_are_not_clauses(analyze_email):
    hop = analyze_email('Received: from a.example (nested (by fake.example; ignored)) by b.example with ESMTPS; Thu, 01 Oct 2026 12:00:00 +0000\n').route[0]
    assert hop.from_endpoint.hostname == "a.example"
    assert hop.by.hostname == "b.example"
    assert hop.timestamp_raw == "Thu, 01 Oct 2026 12:00:00 +0000"


@pytest.mark.parametrize("raw,ip,scope", [
    ("[192.168.1.10]", "192.168.1.10", "private"),
    ("[IPv6:2001:db8::1]", "2001:db8::1", "documentation"),
    ("[fc00::1]", "fc00::1", "private"),
    ("[127.0.0.1]", "127.0.0.1", "loopback"),
    ("[169.254.1.2]", "169.254.1.2", "link_local"),
    ("[192.0.2.25]", "192.0.2.25", "documentation"),
    ("[8.8.8.8]", "8.8.8.8", "public"),
])
def test_address_classification(analyze_email, raw, ip, scope):
    hop = analyze_email(f"Received: from a.example ({raw}) by b.example; Thu, 01 Oct 2026 12:00:00 +0000\n").route[0]
    assert hop.from_endpoint.ip == ip
    assert hop.from_endpoint.ip_scope == scope


def test_multiple_ip_candidates_are_ambiguous(analyze_email):
    hop = analyze_email("Received: from a.example ([192.0.2.1] [192.0.2.2]) by b.example; Thu, 01 Oct 2026 12:00:00 +0000\n").route[0]
    assert hop.from_endpoint.ip is None
    assert hop.from_endpoint.ip_scope == "ambiguous"
    assert hop.from_endpoint.ip_candidates == ["192.0.2.1", "192.0.2.2"]


def test_invalid_ip_is_not_accepted(analyze_email):
    hop = analyze_email("Received: from a.example ([999.1.1.1]) by b.example\n").route[0]
    assert hop.from_endpoint.ip is None


def test_partial_received_remains_visible(analyze_email):
    report = analyze_email("Received: by mx.recipient.example with ESMTP\n")
    assert report.route[0].parse_status == "partial"
    assert report.route[0].by.hostname == "mx.recipient.example"
    assert report.route[0].timestamp is None
    assert any(f.code == "RECEIVED_PARTIAL" for f in report.warnings)


def test_unparsed_received_still_has_hop(analyze_email):
    report = analyze_email("Received: nonsense\n")
    assert len(report.route) == 1
    assert report.route[0].parse_status == "unparsed"


@pytest.mark.parametrize("date,status,timestamp", [
    ("Thu, 01 Oct 2026 20:00:00 +0800", "known", "2026-10-01T12:00:00Z"),
    ("Thu, 01 Oct 2026 12:00:00 -0000", "utc_local_offset_unknown", "2026-10-01T12:00:00Z"),
    ("Thu, 01 Oct 2026 12:00:00", "missing", None),
    ("Thu, 01 Oct 2026 12:00:00 XYZ", "invalid", None),
    ("bad date", "invalid", None),
])
def test_timezone_interpretation(analyze_email, date, status, timestamp):
    hop = analyze_email(f"Received: from a.example by b.example; {date}\n").route[0]
    assert hop.timezone_status == status
    assert hop.model_dump(mode="json", by_alias=True)["timestamp"] == timestamp


def test_missing_semicolon_does_not_guess_date(analyze_email):
    hop = analyze_email("Received: from a.example by b.example Thu, 01 Oct 2026 12:00:00 +0000\n").route[0]
    assert hop.timestamp is None


def test_utc_conversion_overflow_is_a_defect(analyze_email):
    report = analyze_email("Received: from a.example by b.example; Fri, 31 Dec 9999 23:59:59 -1200\n")
    assert report.route[0].timestamp is None
    assert any(d.code == "INVALID_RECEIVED_DATE" for d in report.defects)


def test_quoted_queue_id_and_recipient_are_not_truncated(analyze_email):
    report = analyze_email('Received: from a.example by b.example with ESMTP id "queue item" for <"first last"@recipient.example>; Thu, 01 Oct 2026 12:00:00 +0000\n')
    assert report.route[0].queue_id == "queue item"
    assert report.route[0].recipient == '"first last"@recipient.example'


def test_unbalanced_received_comment_is_observable(analyze_email):
    report = analyze_email("Received: from a.example by b.example (unterminated\n")
    assert any(d.code == "UNBALANCED_HEADER_SYNTAX" for d in report.defects)
