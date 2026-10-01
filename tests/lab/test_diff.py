import base64

import pytest

from mailtrace import analyze
from mailtrace_lab import compare_headers


def test_prefix_received_is_added_not_reordered():
    before = b"Received: from a by b; Thu, 01 Oct 2026 12:00:00 +0000\r\nSubject: x\r\n\r\n"
    after = b"Received: from b by c; Thu, 01 Oct 2026 12:00:01 +0000\r\n" + before
    report = compare_headers(before, after, before_id="s1", after_id="s2")
    assert report.summary["added"] == 1
    assert report.summary.get("order_changed", 0) == 0
    assert report.changes[0].after[0].snapshot_id == "s2"


def test_unique_modification_between_anchors():
    before = b"Subject: top\r\nReceived: from a by b; Thu, 01 Oct 2026 12:00:00 +0000\r\nTo: z@example.test\r\n\r\n"
    after = b"Received: from b by c; Thu, 01 Oct 2026 12:00:01 +0000\r\n" + before.replace(b"from a by b", b"from a by d")
    result = compare_headers(before, after)
    assert result.summary["added"] == 1
    change = next(item for item in result.changes if item.kind == "value_changed")
    assert change.received_changes["by"]["before"]["hostname"] == "b"
    assert change.received_changes["by"]["after"]["hostname"] == "d"


def test_folding_equivalence_without_arbitrary_whitespace_normalization():
    change = compare_headers(b"Subject: one two\r\n\r\n", b"Subject: one\r\n two\r\n\r\n")
    assert change.summary["format_changed"] == 1
    changed = compare_headers(b'Subject: "a b"\r\n\r\n', b'Subject: "a  b"\r\n\r\n')
    assert changed.summary["value_changed"] == 1


def test_reorder_and_duplicates():
    result = compare_headers(b"From: a\r\nTo: b\r\n\r\n", b"To: b\r\nFrom: a\r\n\r\n")
    assert result.summary["order_changed"] >= 1
    uncertain = compare_headers(b"From: a\r\nFrom: b\r\n\r\n", b"From: c\r\nFrom: d\r\n\r\n")
    assert uncertain.summary["ambiguous"] == 1
    assert not any(item.kind == "value_changed" for item in uncertain.changes)


def test_binary_evidence_and_malformed_candidates():
    before = b"From: a\r\nBroken\r\nX-Binary: \xff\r\n\r\nbody"
    after = before.replace(b"\xff", b"\xfe")
    report = compare_headers(before, after, capture_gap=True)
    change = next(item for item in report.changes if item.kind == "value_changed")
    field = change.before[0]
    header = base64.b64decode(analyze(before).source.header_base64)
    assert header[field.start_byte:field.end_byte] == b"X-Binary: \xff\r\n"
    assert report.capture_gap
    assert report.attribution is None


def test_identical_duplicate_instances_not_claimed_as_unique():
    result = compare_headers(b"X: a\r\nX: a\r\n\r\n", b"X: a\r\nX: a\r\n\r\n")
    assert result.summary.get("added", 0) == 0
    assert any(item.kind == "ambiguous" for item in result.changes)


def test_nameless_malformed_lines_do_not_invent_correspondence():
    result = compare_headers(b"Broken\r\n\r\n", b"CompletelyDifferent\r\n\r\n")
    assert result.summary["value_changed"] == 0
    assert result.summary["added"] == result.summary["removed"] == 1


def test_received_component_lookup_does_not_rescan_entire_routes():
    from mailtrace_lab import CaseSpec, forge_case
    class CountedRoute(list):
        scans = 0
        def __iter__(self):
            self.scans += 1
            return super().__iter__()
    raw = forge_case(CaseSpec(received_count=100)).raw
    changed = raw.replace(b"\r\n", b"\n")
    first, second = analyze(raw), analyze(changed)
    first.route, second.route = CountedRoute(first.route), CountedRoute(second.route)
    result = compare_headers(raw, changed, before_report=first, after_report=second)
    assert result.summary["format_changed"] >= 100
    assert first.route.scans <= 2 and second.route.scans <= 2


def test_cached_reports_cannot_substitute_foreign_evidence():
    raw = b"Subject: input\r\n\r\n"
    foreign = analyze(b"Subject: foreign\r\n\r\n")
    with pytest.raises(ValueError):
        compare_headers(raw, raw, before_report=foreign)
