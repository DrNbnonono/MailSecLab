import importlib.util
import json

import pytest


@pytest.fixture
def client():
    assert importlib.util.find_spec("mailtrace_api") is not None, "API is not implemented"
    from fastapi.testclient import TestClient
    from mailtrace_api.main import app
    return TestClient(app)


def test_json_contract(client, basic_bytes):
    from mailtrace import analyze
    text = basic_bytes.decode("ascii")
    response = client.post("/api/v1/analyze", json={"raw_email": text})
    assert response.status_code == 200
    assert response.json() == analyze(text).model_dump(mode="json", by_alias=True)
    assert response.headers["cache-control"] == "no-store"


def test_upload_keeps_original_bytes(client, basic_bytes):
    from mailtrace import analyze
    response = client.post("/api/v1/analyze/file", files={"file": ("sample.eml", basic_bytes, "message/rfc822")})
    assert response.status_code == 200
    assert response.json() == analyze(basic_bytes).model_dump(mode="json", by_alias=True)


@pytest.mark.parametrize("payload", [{"raw_email": ""}, {"raw_email": "  "}, {"raw_email": 123}, {"raw_email": "Subject: x", "chain_limit": 0}, {"raw_email": "Subject: x", "chain_limit": True}])
def test_bad_input(client, payload):
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422


def test_validation_error_does_not_echo_input(client):
    response = client.post("/api/v1/analyze", json={"raw_email": "SECRET-MAIL-CONTENT", "chain_limit": "SECRET-PARAM"})
    assert response.status_code == 422
    assert "SECRET" not in response.text


def test_empty_upload(client):
    assert client.post("/api/v1/analyze/file", files={"file": ("empty.eml", b"")}).status_code == 422


def test_invalid_upload_chain_limit(client):
    assert client.post("/api/v1/analyze/file", files={"file": ("a.eml", b"Subject: a")}, data={"chain_limit": "0"}).status_code == 422


def test_content_length_limit(client):
    response = client.post("/api/v1/analyze", content=b"{}", headers={"Content-Length": str(12 * 1024 * 1024 + 1), "Content-Type": "application/json"})
    assert response.status_code == 413


def test_extremely_long_content_length(client):
    response = client.post("/api/v1/analyze", content=b"{}", headers={"Content-Length": "9" * 5000, "Content-Type": "application/json"})
    assert response.status_code == 413


def test_streamed_body_limit_without_length(client):
    def chunks():
        for _ in range(13):
            yield b"x" * (1024 * 1024)
    response = client.post("/api/v1/analyze", content=chunks(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_input_limit(client):
    response = client.post("/api/v1/analyze", json={"raw_email": "x" * (10 * 1024 * 1024 + 1)})
    assert response.status_code == 413


def test_bad_json(client):
    response = client.post("/api/v1/analyze", content=b'{"secret":"PRIVATE",', headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert "PRIVATE" not in response.text


def test_health_and_openapi(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    spec = client.get("/openapi.json").json()
    assert "/api/v1/analyze" in spec["paths"]
    assert "/api/v1/analyze/file" in spec["paths"]
