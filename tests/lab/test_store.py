import json
import zipfile
from io import BytesIO

import pytest

from mailtrace_lab import CaseSpec, SweepSpec, ExperimentStore
from mailtrace_lab.models import CaptureInput


def test_archive_reopen_reproduce_and_exports(tmp_path):
    store = ExperimentStore(tmp_path)
    run = store.forge(CaseSpec(), SweepSpec(axis="received_count", values=[0, 2, 51]))
    assert run.kind == "parameter_sweep"
    assert run.diffs == []
    reopened = ExperimentStore(tmp_path).load(run.id)
    assert reopened == run
    reproduced = store.reproduce(run.id)
    assert reproduced.id != run.id
    assert [s.metrics.input_sha256 for s in reproduced.snapshots] == [s.metrics.input_sha256 for s in run.snapshots]
    with zipfile.ZipFile(BytesIO(store.export_zip(run.id))) as archive:
        assert "manifest.json" in archive.namelist()
        assert len([name for name in archive.namelist() if name.endswith(".eml")]) == 3
    assert b"received_count" in store.export_csv(run.id)
    assert len(store.history()["items"]) == 2


def test_ordered_capture_comparison_and_no_claimed_delivery(tmp_path):
    store = ExperimentStore(tmp_path)
    run = store.compare([CaptureInput(raw=b"Subject: a\r\n\r\n", label="before"),
                         CaptureInput(raw=b"Subject: b\r\n\r\n", label="after", capture_gap=True)])
    assert run.kind == "capture_sequence"
    assert [s.label for s in run.snapshots] == ["before", "after"]
    assert run.snapshots[0].smtp_result is None
    assert store.read_diff(run.id, run.diffs[0].id).capture_gap


def test_tampering_and_missing_files_fail(tmp_path):
    store = ExperimentStore(tmp_path)
    run = store.forge(CaseSpec())
    rawpath = tmp_path / run.id / run.snapshots[0].eml.path
    rawpath.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="完整性|integrity"):
        store.load(run.id)
    rawpath.unlink()
    with pytest.raises(ValueError, match="完整性|integrity"):
        store.load(run.id)


def test_failed_writes_do_not_publish_or_overwrite(tmp_path, monkeypatch):
    store = ExperimentStore(tmp_path)
    original = store.forge(CaseSpec())
    def fail(*args, **kwargs):
        raise OSError("disk unavailable")
    monkeypatch.setattr(store, "_write", fail)
    with pytest.raises(OSError):
        store.forge(CaseSpec())
    assert len(store.history()["items"]) == 1
    assert store.load(original.id) == original


def test_input_limits_and_invalid_paths(tmp_path):
    store = ExperimentStore(tmp_path)
    with pytest.raises(ValueError):
        store.load("../escape")
    with pytest.raises(ValueError):
        store.compare([CaptureInput(raw=b"x", label="only")])
    with pytest.raises(ValueError):
        store.compare([CaptureInput(raw=b"x" * (10 * 1024 * 1024 + 1), label="large"), CaptureInput(raw=b"x", label="other")])


def test_capture_time_requires_explicit_timezone():
    with pytest.raises(ValueError):
        CaptureInput(raw=b"Subject: test\r\n\r\n", captured_at="2026-10-01T12:00:00")
    capture = CaptureInput(raw=b"Subject: test\r\n\r\n", captured_at="2026-10-01T12:00:00Z")
    assert capture.captured_at.utcoffset().total_seconds() == 0


def test_history_pages_and_corrupt_manifest(tmp_path):
    store = ExperimentStore(tmp_path)
    runs = [store.forge(CaseSpec(received_count=0)) for _ in range(51)]
    first = store.history()
    second = store.history(first["next_cursor"])
    assert len(first["items"]) == 50
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None
    assert len({item["id"] for item in first["items"] + second["items"]}) == 51
    (tmp_path / runs[-1].id / "manifest.json").write_bytes(b"corrupt")
    assert store.history()["items"][0]["integrity"] == "failed"
    with pytest.raises(ValueError, match="完整性"):
        store.reproduce(runs[-1].id)


def test_legal_large_case_manifest_can_be_reopened(tmp_path):
    from mailtrace_lab.models import HeaderSpec
    store = ExperimentStore(tmp_path)
    case = CaseSpec(received_count=0, headers=[HeaderSpec(name=f"X-{i}", value="a" * 100000) for i in range(42)])
    run = store.forge(case)
    assert (tmp_path / run.id / "manifest.json").stat().st_size > 4 * 1024 * 1024
    assert store.load(run.id) == run


def test_maximum_case_name_remains_valid_when_snapshot_suffix_is_added(tmp_path):
    run = ExperimentStore(tmp_path).forge(CaseSpec(name="x" * 200))
    assert run.name == "x" * 200
    assert len(run.snapshots[0].label) <= 200


def test_group_count_and_total_bytes_rejected_before_analysis(tmp_path):
    store = ExperimentStore(tmp_path)
    with pytest.raises(ValueError, match="1–20"):
        store.compare([CaptureInput(raw=b"x")] * 21)
    shared = b"x" * (10 * 1024 * 1024)
    with pytest.raises(ValueError, match="50 MiB"):
        store.compare([CaptureInput(raw=shared)] * 6)
