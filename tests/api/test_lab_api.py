import json

import pytest
from fastapi.testclient import TestClient
from mailtrace_api.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAILTRACE_EXPERIMENT_DIR", str(tmp_path))
    return TestClient(app)


def test_forge_archive_download_and_reproduce(client):
    result = client.post("/api/v1/lab/forge", json={"case":{"received_count":2}, "sweep":{"axis":"received_count","values":[0,2,51]}})
    assert result.status_code == 200
    run = result.json()
    assert run["kind"] == "parameter_sweep"
    assert client.get(f"/api/v1/lab/runs/{run['id']}").json() == run
    snapshot_id = run["snapshots"][1]["id"]
    report = client.get(f"/api/v1/lab/runs/{run['id']}/snapshots/{snapshot_id}/report")
    assert len(report.json()["route"]) == 2
    for kind in ("zip", "csv"):
        download = client.get(f"/api/v1/lab/runs/{run['id']}/export/{kind}")
        assert download.status_code == 200
        assert "attachment" in download.headers["content-disposition"]
        assert download.headers["cache-control"] == "no-store"
    assert client.post(f"/api/v1/lab/runs/{run['id']}/reproduce").json()["derived_from"] == run["id"]
    assert len(client.get("/api/v1/lab/runs").json()["items"]) == 2


def test_comparison_preserves_order_and_binary_input(client):
    metadata = [{"label":"first", "mta":"Postfix"}, {"label":"second", "capture_gap":True}]
    result = client.post("/api/v1/lab/compare", data={"metadata":json.dumps(metadata)},
                         files=[("files", ("a.eml", b"Subject: \xff\r\n\r\n")), ("files", ("b.eml", b"Subject: \xfe\r\n\r\n"))])
    assert result.status_code == 200
    run = result.json()
    assert [snapshot["label"] for snapshot in run["snapshots"]] == ["first", "second"]
    diff = client.get(f"/api/v1/lab/runs/{run['id']}/diffs/{run['diffs'][0]['id']}").json()
    assert diff["summary"]["value_changed"] == 1
    assert diff["capture_gap"] and diff["attribution"] is None


def test_errors_and_invalid_paths(client):
    bad = client.post("/api/v1/lab/forge", json={"case":{"received_count":10001,"purpose":"SECRET-CONTENT"}})
    assert bad.status_code == 422 and "SECRET" not in bad.text
    assert client.get("/api/v1/lab/runs/not-an-id").status_code == 422
    assert client.get("/api/v1/lab/runs/" + "a" * 32).status_code == 404
    one = client.post("/api/v1/lab/compare", files={"files":("only.eml", b"Subject: x")})
    assert one.status_code == 422


def test_lab_request_budget_is_separate(client):
    assert client.post("/api/v1/lab/forge", content=b"{}", headers={"Content-Length":str(52*1024*1024+1)}).status_code == 413
    # A >12MiB lab request reaches validation; the normal analyzer remains bounded.
    payload = b" " * (12 * 1024 * 1024 + 1)
    assert client.post("/api/v1/lab/forge", content=payload, headers={"Content-Type":"application/json"}).status_code == 422
    assert client.post("/api/v1/analyze", content=payload, headers={"Content-Type":"application/json"}).status_code == 413


def test_failed_archive_is_not_a_success_and_error_is_sanitized(client, monkeypatch):
    from mailtrace_lab import ExperimentStore
    def fail(*args, **kwargs):
        raise OSError("SECRET disk path and raw mail")
    monkeypatch.setattr(ExperimentStore, "_write", fail)
    result = client.post("/api/v1/lab/forge", json={"case":{}})
    assert result.status_code == 503
    assert "SECRET" not in result.text
    assert client.get("/api/v1/lab/runs").json()["items"] == []


def test_hash_corruption_blocks_reopening_and_download(client):
    from mailtrace_lab import ExperimentStore
    store = ExperimentStore()
    run = client.post("/api/v1/lab/forge", json={"case":{}}).json()
    path = store.root / run["id"] / run["snapshots"][0]["report"]["path"]
    path.write_bytes(b"corrupt")
    for suffix in ("", "/export/zip", "/snapshots/snapshot-001/report"):
        assert client.get(f"/api/v1/lab/runs/{run['id']}{suffix}").status_code == 409
    assert client.post(f"/api/v1/lab/runs/{run['id']}/reproduce").status_code == 409
