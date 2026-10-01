import importlib.util
import json
from pathlib import Path

import pytest


def test_contract_example_roundtrips():
    assert importlib.util.find_spec("mailtrace") is not None, "Core package is not implemented"
    from mailtrace.models.report import MailReport

    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "docs/contracts/report-v0.1.example.json").read_text(encoding="utf-8"))
    report = MailReport.model_validate(data)
    assert report.model_dump(mode="json", by_alias=True) == data
    assert report.route[0].from_endpoint.hostname == "laptop.local"


def test_options_reject_non_positive_and_non_integer_limit():
    from mailtrace.models.report import AnalysisOptions
    from pydantic import ValidationError

    for limit in (0, -1, True, 1.5, "2"):
        with pytest.raises(ValidationError):
            AnalysisOptions(chain_limit=limit)


def test_verified_cannot_be_set_true():
    from mailtrace.models.report import AuthSummary
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AuthSummary(verified=True)
