import hashlib

import pytest

from mailtrace_lab import CaseSpec, SweepSpec, forge_case, expand_cases


@pytest.mark.parametrize("count", [0, 50, 51, 200])
def test_counts_and_determinism(count):
    spec = CaseSpec(received_count=count)
    first = forge_case(spec)
    second = forge_case(spec)
    assert first.raw == second.raw
    assert first.metrics.input_sha256 == hashlib.sha256(first.raw).hexdigest()
    assert first.metrics.candidate_received_count == count
    assert first.metrics.recognized_received_count == count
    assert first.report.source.input_kind == "bytes"


@pytest.mark.parametrize("length", [997, 998, 999])
def test_exact_max_line(length):
    result = forge_case(CaseSpec(max_line_bytes=length))
    assert result.metrics.max_line_bytes == length


def test_exact_header_size_and_folded_lf():
    result = forge_case(CaseSpec(header_bytes=4096, max_line_bytes=200, folding="tab", newline="lf"))
    assert result.metrics.header_bytes == 4096
    assert result.metrics.max_line_bytes == 200
    assert b"\n\tby " in result.raw
    assert b"\r" not in result.raw


def test_ambiguity_and_order():
    from mailtrace_lab.models import HeaderSpec
    spec = CaseSpec(received_position="last", pre_colon_space=True,
                    headers=[HeaderSpec(name="From", value="a@example.test"), HeaderSpec(name="From", value="b@example.test"),
                             HeaderSpec(name="Message-ID", value="<one@example.test>"), HeaderSpec(name="Message-ID", value="<two@example.test>")])
    result = forge_case(spec)
    assert result.raw.startswith(b"From :")
    assert result.metrics.candidate_received_count == 2
    assert result.metrics.recognized_received_count == 0
    assert [field.name for field in result.report.headers][:4] == ["From", "From", "Message-ID", "Message-ID"]


def test_unsatisfiable_dimensions():
    with pytest.raises(ValueError, match="最小|minimum"):
        forge_case(CaseSpec(header_bytes=20))
    with pytest.raises(ValueError, match="最小|minimum"):
        forge_case(CaseSpec(max_line_bytes=10))


def test_sweep_changes_only_one_dimension():
    original = CaseSpec(seed=17, folding="space")
    cases = expand_cases(original, SweepSpec(axis="received_count", values=[0, 50, 51, 200]))
    assert [case.received_count for case in cases] == [0, 50, 51, 200]
    for case in cases:
        assert case.model_dump(exclude={"received_count"}) == original.model_dump(exclude={"received_count"})


def test_received_sweep_keeps_existing_hop_bytes():
    first = forge_case(CaseSpec(received_count=2))
    second = forge_case(CaseSpec(received_count=3))
    previous = [field.raw for field in first.report.headers if field.name == "Received"]
    following = [field.raw for field in second.report.headers if field.name == "Received"]
    assert following[1:] == previous


@pytest.mark.parametrize("payload", [{"received_count":10001}, {"received_count":True}, {"base_time":"2026-01-01"},
                                      {"headers":[{"name":"From", "value":"a\nB: c"}]}])
def test_invalid_case(payload):
    with pytest.raises(ValueError):
        CaseSpec.model_validate(payload)


def test_maximum_received_count_remains_complete():
    sample = forge_case(CaseSpec(received_count=10000))
    assert sample.metrics.candidate_received_count == sample.metrics.recognized_received_count == 10000
    assert len(sample.report.route) == 10000
