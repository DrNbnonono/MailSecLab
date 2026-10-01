import pytest


def test_deterministic_report(analyze_email, basic_bytes):
    assert analyze_email(basic_bytes).model_dump() == analyze_email(basic_bytes).model_dump()


def test_text_and_bytes_match_except_input_kind(analyze_email):
    raw = "Subject: 中文\n"
    first = analyze_email(raw).model_dump()
    second = analyze_email(raw.encode()).model_dump()
    assert first["source"].pop("input_kind") == "text_utf8"
    assert second["source"].pop("input_kind") == "bytes"
    assert first == second


@pytest.mark.parametrize("raw,error", [(b"", ValueError), ("", ValueError), (123, TypeError), (None, TypeError)])
def test_input_errors(analyze_email, raw, error):
    with pytest.raises(error):
        analyze_email(raw)


def test_no_received_or_auth_is_not_malicious(analyze_email):
    report = analyze_email("Subject: normal\n")
    assert report.route == []
    assert report.warnings == []
    assert report.authentication.summary.spf.status == "unknown"
