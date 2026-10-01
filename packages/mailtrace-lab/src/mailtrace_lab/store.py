from datetime import datetime, timezone
import csv
import hashlib
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import re
from uuid import uuid4
import zipfile

from mailtrace import MailReport, analyze

from .diff import compare_headers
from .forge import expand_cases, forge_case, measure
from .models import (Artifact, CaptureInput, CaseSpec, DiffReport, ExperimentManifest, MAX_ITEMS,
                     MAX_MESSAGE_BYTES, MAX_RUN_BYTES, Snapshot, StoredDiff, SweepSpec)


class ArchiveIntegrityError(ValueError):
    pass


# Case parameters are embedded, and JSON escaping can expand their bytes.
# This bounds all legal <=50 MiB groups plus fixed metadata with ample margin.
MAX_MANIFEST_BYTES = MAX_RUN_BYTES * 8


class ExperimentStore:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("MAILTRACE_EXPERIMENT_DIR") or Path.cwd() / "local-experiments").resolve()

    def _run_path(self, run_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise ValueError("实验 ID 无效。")
        path = self.root / run_id
        if path.is_symlink() or path.resolve().parent != self.root:
            raise ArchiveIntegrityError("实验完整性检查失败：目录位置无效。")
        return path

    def _artifact_path(self, directory: Path, relative: str) -> Path:
        if not re.fullmatch(r"(?:messages/snapshot-\d{3}\.eml|reports/snapshot-\d{3}\.json|cases/snapshot-\d{3}\.json|diffs/diff-\d{3}\.json)", relative):
            raise ArchiveIntegrityError("实验完整性检查失败：产物路径无效。")
        path = directory / relative
        if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            raise ArchiveIntegrityError("实验完整性检查失败：产物位置无效。")
        return path

    def _write(self, directory: Path, relative: str, data: bytes) -> Artifact:
        path = self._artifact_path(directory, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as file:
            file.write(data)
        return Artifact(path=relative, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))

    @staticmethod
    def _json(value) -> bytes:
        return value.model_dump_json(by_alias=True, indent=2).encode("utf-8")

    @staticmethod
    def _bounded_inputs(inputs):
        if not 1 <= len(inputs) <= MAX_ITEMS:
            raise ValueError("实验须包含 1–20 份样本。")
        total = 0
        for item in inputs:
            if not item.raw or len(item.raw) > MAX_MESSAGE_BYTES:
                raise ValueError("每封邮件须非空且不超过 10 MiB。")
            total += len(item.raw)
        if total > MAX_RUN_BYTES:
            raise ValueError("实验原始邮件累计超过 50 MiB。")

    def forge(self, case: CaseSpec, sweep: SweepSpec | None = None, *, derived_from=None):
        cases = expand_cases(case, sweep)
        samples, total = [], 0
        for spec in cases:
            sample = forge_case(spec)
            total += len(sample.raw)
            if total > MAX_RUN_BYTES:
                raise ValueError("生成样本累计超过 50 MiB。")
            samples.append(sample)
        inputs = []
        for index, sample in enumerate(samples, 1):
            suffix = f" · {index}"
            inputs.append(CaptureInput(raw=sample.raw, label=case.name[:200-len(suffix)] + suffix))
        return self._save("parameter_sweep" if sweep else "generated_sample", inputs,
                          [sample.report for sample in samples], cases, sweep, case.name, derived_from)

    def compare(self, inputs: list[CaptureInput], *, name="逐跳采集对比", derived_from=None):
        if len(inputs) < 2:
            raise ValueError("逐跳比较需要至少两份快照。")
        self._bounded_inputs(inputs)
        return self._save("capture_sequence", inputs, [analyze(item.raw) for item in inputs], [], None, name[:200], derived_from)

    def _save(self, kind, inputs, reports, cases, sweep, name, derived_from):
        self._bounded_inputs(inputs)
        self.root.mkdir(parents=True, exist_ok=True)
        run_id = uuid4().hex
        directory = self.root / f".pending-{run_id}"
        directory.mkdir(exist_ok=False)
        snapshots, differences = [], []
        # On failure retain the staging evidence, but never publish a complete run.
        for i, (item, report) in enumerate(zip(inputs, reports), 1):
            snapshot_id = f"snapshot-{i:03}"
            eml = self._write(directory, f"messages/{snapshot_id}.eml", item.raw)
            report_artifact = self._write(directory, f"reports/{snapshot_id}.json", self._json(report))
            case = cases[i-1] if cases else None
            case_artifact = self._write(directory, f"cases/{snapshot_id}.json", self._json(case)) if case else None
            snapshots.append(Snapshot(**item.model_dump(exclude={"raw"}), id=snapshot_id, position=i,
                                      source="generated" if cases else "imported", metrics=measure(item.raw, report),
                                      case=case, eml=eml, report=report_artifact, case_artifact=case_artifact))
        if kind == "capture_sequence":
            for i in range(len(inputs)-1):
                diff_id = f"diff-{i+1:03}"
                diff = compare_headers(inputs[i].raw, inputs[i+1].raw, before_id=snapshots[i].id,
                                       after_id=snapshots[i+1].id, capture_gap=inputs[i+1].capture_gap,
                                       before_report=reports[i], after_report=reports[i+1])
                artifact = self._write(directory, f"diffs/{diff_id}.json", self._json(diff))
                differences.append(StoredDiff(id=diff_id, before_id=diff.before_id, after_id=diff.after_id, summary=diff.summary, report=artifact))
        manifest = ExperimentManifest(id=run_id, kind=kind, name=name, created_at=datetime.now(timezone.utc),
                                      sweep=sweep, derived_from=derived_from, snapshots=snapshots, diffs=differences)
        data = self._json(manifest)
        if len(data) > MAX_MANIFEST_BYTES:
            raise ValueError("实验清单超过存储上限；未发布成功实验。")
        (directory / "manifest.json").write_bytes(data)
        (directory / "manifest.sha256").write_text(hashlib.sha256(data).hexdigest(), encoding="ascii")
        target = self._run_path(run_id)
        if target.exists():
            raise OSError("实验 ID 冲突；未覆盖已有数据。")
        directory.rename(target)
        return manifest

    @staticmethod
    def _artifacts(manifest):
        return [artifact for snapshot in manifest.snapshots for artifact in (snapshot.eml, snapshot.report, snapshot.case_artifact) if artifact] + [diff.report for diff in manifest.diffs]

    def _read_verified(self, directory, artifact):
        path = self._artifact_path(directory, artifact.path)
        try:
            if path.stat().st_size != artifact.size_bytes:
                raise ArchiveIntegrityError("实验完整性检查失败：文件大小改变。")
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact.sha256:
                raise ArchiveIntegrityError("实验完整性检查失败：文件哈希改变。")
            return data
        except OSError:
            raise ArchiveIntegrityError("实验完整性检查失败：产物缺失或不可读。") from None

    def load(self, run_id: str) -> ExperimentManifest:
        directory = self._run_path(run_id)
        if not directory.exists():
            raise FileNotFoundError("实验不存在。")
        try:
            manifest_path = directory / "manifest.json"
            if manifest_path.is_symlink() or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
                raise ValueError("manifest size/path invalid")
            data = manifest_path.read_bytes()
            digest_path = directory / "manifest.sha256"
            if digest_path.is_symlink() or digest_path.stat().st_size != 64:
                raise ValueError("manifest digest invalid")
            if hashlib.sha256(data).hexdigest() != digest_path.read_text(encoding="ascii"):
                raise ValueError("manifest changed")
            manifest = ExperimentManifest.model_validate_json(data)
            if manifest.id != run_id:
                raise ValueError("manifest ID mismatch")
        except (OSError, ValueError):
            raise ArchiveIntegrityError("实验完整性检查失败：清单缺失、损坏或已修改。") from None
        for artifact in self._artifacts(manifest):
            self._read_verified(directory, artifact)
        return manifest

    def read_report(self, run_id, snapshot_id) -> MailReport:
        manifest = self.load(run_id)
        snapshot = next((item for item in manifest.snapshots if item.id == snapshot_id), None)
        if not snapshot:
            raise FileNotFoundError("快照不存在。")
        return MailReport.model_validate_json(self._read_verified(self._run_path(run_id), snapshot.report))

    def read_diff(self, run_id, diff_id) -> DiffReport:
        manifest = self.load(run_id)
        diff = next((item for item in manifest.diffs if item.id == diff_id), None)
        if not diff:
            raise FileNotFoundError("差分不存在。")
        return DiffReport.model_validate_json(self._read_verified(self._run_path(run_id), diff.report))

    def read_message(self, run_id, snapshot_id) -> bytes:
        manifest = self.load(run_id)
        snapshot = next((item for item in manifest.snapshots if item.id == snapshot_id), None)
        if not snapshot:
            raise FileNotFoundError("快照不存在。")
        return self._read_verified(self._run_path(run_id), snapshot.eml)

    def history(self, cursor: str | None = None, limit=50):
        if not 1 <= limit <= 50:
            raise ValueError("历史页大小须为 1–50。")
        if cursor is not None:
            self._run_path(cursor)
        if not self.root.exists():
            return {"items":[], "next_cursor":None}
        entries = sorted((p for p in self.root.iterdir() if re.fullmatch(r"[0-9a-f]{32}", p.name) and p.is_dir()),
                         key=lambda path:(path.stat().st_mtime_ns, path.name), reverse=True)
        if cursor:
            index = next((i for i, path in enumerate(entries) if path.name == cursor), None)
            if index is None:
                raise ValueError("历史游标无效。")
            entries = entries[index+1:]
        items = []
        for path in entries[:limit]:
            try:
                run = self.load(path.name)
                items.append({"id":run.id, "name":run.name, "kind":run.kind, "created_at":run.created_at.isoformat(),
                              "snapshot_count":len(run.snapshots), "integrity":"ok"})
            except (ArchiveIntegrityError, FileNotFoundError):
                items.append({"id":path.name, "name":"归档完整性异常", "kind":"unknown", "created_at":None,
                              "snapshot_count":None, "integrity":"failed"})
        return {"items":items, "next_cursor":entries[limit-1].name if len(entries) > limit else None}

    def reproduce(self, run_id):
        run = self.load(run_id)
        if run.kind in {"generated_sample", "parameter_sweep"}:
            first = run.snapshots[0].case
            if first is None:
                raise ArchiveIntegrityError("实验完整性检查失败：缺少生成参数。")
            cases = expand_cases(first, run.sweep)
            # Refuse to publish a reproduction if the current generator changed.
            for case, snapshot in zip(cases, run.snapshots):
                if forge_case(case).metrics.input_sha256 != snapshot.metrics.input_sha256:
                    raise ArchiveIntegrityError("复现字节不同；请核对生成器版本。")
            return self.forge(first, run.sweep, derived_from=run.id)
        inputs = [CaptureInput(**snapshot.model_dump(include=set(CaptureInput.model_fields)-{"raw"}),
                               raw=self.read_message(run.id, snapshot.id)) for snapshot in run.snapshots]
        return self.compare(inputs, name=run.name, derived_from=run.id)

    def export_zip(self, run_id):
        run = self.load(run_id)
        directory = self._run_path(run_id)
        output = BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", self._json(run))
            archive.writestr("manifest.sha256", hashlib.sha256(self._json(run)).hexdigest())
            for artifact in self._artifacts(run):
                archive.writestr(artifact.path, self._read_verified(directory, artifact))
        return output.getvalue()

    def export_csv(self, run_id):
        run = self.load(run_id)
        output = StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["snapshot_id", "received_count", "recognized_received_count", "header_bytes", "max_line_bytes", "input_bytes", "input_sha256", "transport_result"])
        for snapshot in run.snapshots:
            m = snapshot.metrics
            writer.writerow([snapshot.id, m.candidate_received_count, m.recognized_received_count, m.header_bytes,
                             m.max_line_bytes, m.input_bytes, m.input_sha256, "not_measured"])
        return output.getvalue().encode("utf-8-sig")
