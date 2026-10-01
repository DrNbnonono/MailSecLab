import pytest


def test_multiple_authserv_and_quoted_reason(analyze_email):
    raw = 'Authentication-Results: mx.one.example; dkim=pass reason="a;b" header.d=one.example\nAuthentication-Results: mx.two.example; dkim=fail header.d=two.example\n'
    report = analyze_email(raw)
    assertions = report.authentication.assertions
    assert [a.authserv_id for a in assertions] == ["mx.one.example", "mx.two.example"]
    assert assertions[0].reason == "a;b"
    assert report.authentication.summary.dkim.status == "mixed"
    assert all(not a.verified and a.trust == "unassessed" for a in assertions)
    assert not report.warnings


def test_nested_comment_is_not_authentication(analyze_email):
    report = analyze_email("Authentication-Results: mx.example (comment (spf=pass;)); dkim=fail (by checker; spf=pass) header.d=sender.example\n")
    assert len(report.authentication.assertions) == 1
    assert report.authentication.summary.spf.status == "unknown"


def test_duplicate_properties_preserved(analyze_email):
    report = analyze_email("Authentication-Results: mx.example; spf=pass smtp.mailfrom=one.example smtp.mailfrom=two.example\n")
    assert [p.value for p in report.authentication.assertions[0].properties] == ["one.example", "two.example"]


@pytest.mark.parametrize("value", ["mx.example; none", "mx.example"])
def test_no_assertion_is_unknown(analyze_email, value):
    report = analyze_email(f"Authentication-Results: {value}\n")
    assert report.authentication.summary.spf.status == "unknown"
    assert report.authentication.assertions == []


def test_unknown_method_and_result_retained(analyze_email):
    report = analyze_email("Authentication-Results: mx.example; custom=pass; spf=madeup\n")
    assert [a.method for a in report.authentication.assertions] == ["custom", "spf"]
    assert report.authentication.summary.spf.status == "unrecognized"
    assert report.authentication.summary.spf.reported_results == ["madeup"]
    assert any(d.code == "UNSUPPORTED_AUTH_RESULT" for d in report.defects)


def test_signatures_and_arc_do_not_imply_verification(analyze_email):
    report = analyze_email("DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=design; b=AA==\nARC-Seal: i=1\nARC-Message-Signature: i=1\nARC-Authentication-Results: i=1; mx.example; spf=pass\n")
    assert report.authentication.summary.dkim.status == "unknown"
    assert report.authentication.summary.spf.status == "unknown"
    assert report.authentication.dkim_signatures[0].domain == "sender.example"
    assert len(report.authentication.arc_headers) == 3


def test_received_spf_does_not_override_auth_results(analyze_email):
    report = analyze_email("Received-SPF: fail (source not authorized)\nAuthentication-Results: mx.example; spf=pass\n")
    assert report.authentication.summary.spf.reported_results == ["pass"]
    assert report.authentication.received_spf[0].result == "fail"


def test_quoted_authserv_id_is_complete(analyze_email):
    report = analyze_email('Authentication-Results: "mx one.example"; spf=pass\n')
    assert report.authentication.assertions[0].authserv_id == "mx one.example"


def test_auth_cfws_around_version_and_property_dot(analyze_email):
    report = analyze_email("Authentication-Results: mx.example; spf / 1 = pass smtp (annotation) . mailfrom = sender.example\n")
    assertion = report.authentication.assertions[0]
    assert assertion.method == "spf"
    assert assertion.properties[0].name == "smtp.mailfrom"
    assert assertion.properties[0].value == "sender.example"


@pytest.mark.parametrize("value", [
    "mx.example; spf=pass (unterminated; dkim=fail",
    'mx.example; spf=pass reason="unterminated',
])
def test_unbalanced_auth_syntax_is_observable(analyze_email, value):
    report = analyze_email(f"Authentication-Results: {value}\n")
    assert any(d.code == "UNBALANCED_HEADER_SYNTAX" for d in report.defects)
