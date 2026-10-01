import pytest


def route_email(edges, times=None):
    times = times or ["12:00:00"] * len(edges)
    fields = [f"Received: from {a} by {b}; Thu, 01 Oct 2026 {t} +0000\n" for (a, b), t in zip(edges, times)]
    return "".join(reversed(fields))


def test_basic_route_matches_design_example(analyze_email, basic_bytes):
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    expected = json.loads((root / "docs/contracts/report-v0.1.example.json").read_text(encoding="utf-8"))
    assert analyze_email(basic_bytes).model_dump(mode="json", by_alias=True) == expected


def test_negative_delay_does_not_reorder_route(analyze_email):
    report = analyze_email(route_email([("a.example", "b.example"), ("b.example", "c.example")], ["12:01:00", "12:00:00"]))
    assert report.route[0].from_endpoint.hostname == "a.example"
    assert report.route[1].delay_seconds == -60
    assert report.route_summary.total_observed_delay_seconds == -60
    assert any(f.code == "TIMESTAMP_REVERSED" for f in report.warnings)


def test_missing_timestamp_makes_total_unknown(analyze_email):
    report = analyze_email("Received: from b.example by c.example\nReceived: from a.example by b.example; Thu, 01 Oct 2026 12:00:00 +0000\n")
    assert report.route_summary.total_observed_delay_seconds is None
    assert report.route[1].delay_seconds is None


@pytest.mark.parametrize("count,expected", [(50, False), (51, True)])
def test_chain_threshold(analyze_email, count, expected):
    report = analyze_email("Received: by mx.example\n" * count)
    assert any(f.code == "LONG_RECEIVED_CHAIN" for f in report.warnings) is expected


@pytest.mark.parametrize("edges,loop,discontinuity", [
    ([("a.example", "b.example"), ("B.EXAMPLE.", "c.example")], False, False),
    ([("a.example", "b.example"), ("d.example", "c.example")], False, True),
    ([("a.example", "b.example"), ("b.example", "a.example")], True, False),
    ([("a.example", "b.example"), ("a.example", "b.example")], True, True),
    ([("a.example", "b.example"), ("c.example", "a.example")], False, True),
])
def test_routing_findings(analyze_email, edges, loop, discontinuity):
    report = analyze_email(route_email(edges))
    codes = {f.code for f in report.warnings}
    assert ("POSSIBLE_ROUTING_LOOP" in codes) is loop
    assert ("ROUTE_DISCONTINUITY" in codes) is discontinuity


def test_private_ip_only_for_private_ranges(analyze_email):
    report = analyze_email("Received: from a.example ([192.0.2.1]) by b.example\n")
    assert not any(f.code == "PRIVATE_IP_EXPOSED" for f in report.warnings)
