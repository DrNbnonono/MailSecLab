from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def basic_bytes():
    return (ROOT / "docs/contracts/basic-example.eml").read_bytes()


@pytest.fixture
def analyze_email():
    import mailtrace

    analyze = getattr(mailtrace, "analyze", None)
    assert callable(analyze), "Public analyze API is not implemented"
    return analyze
