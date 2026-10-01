import json
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from mailtrace_lab import CaseSpec, DiffReport, ExperimentManifest, ExperimentStore, SweepSpec
from mailtrace_lab.models import CaptureInput, CaptureMetadata, MAX_ITEMS, MAX_MESSAGE_BYTES, MAX_RUN_BYTES, Model
from mailtrace_lab.store import ArchiveIntegrityError

router = APIRouter(prefix="/api/v1/lab", tags=["Research workspace"])


class ForgeRequest(Model):
    case: CaseSpec
    sweep: SweepSpec | None = None


async def lab_call(action, *args):
    try:
        return await run_in_threadpool(action, *args)
    except FileNotFoundError:
        raise HTTPException(404, "实验或产物不存在。") from None
    except ArchiveIntegrityError as error:
        raise HTTPException(409, str(error)) from None
    except ValidationError:
        raise HTTPException(422, "实验参数或归档结构无效。") from None
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    except OSError:
        raise HTTPException(503, "实验目录不可读写；未发布成功实验，请检查本地存储。") from None


@router.post("/forge")
async def forge(payload: ForgeRequest) -> ExperimentManifest:
    return await lab_call(ExperimentStore().forge, payload.case, payload.sweep)


@router.post("/compare")
async def compare(files: Annotated[list[UploadFile], File()], metadata: Annotated[str | None, Form()] = None) -> ExperimentManifest:
    try:
        if not 2 <= len(files) <= MAX_ITEMS:
            raise HTTPException(422, "比较须上传 2–20 份有序快照。")
        try:
            entries = json.loads(metadata) if metadata is not None else [{"label":(file.filename or "快照")[:200]} for file in files]
            if not isinstance(entries, list) or len(entries) != len(files):
                raise ValueError("metadata length mismatch")
            labels = [CaptureMetadata.model_validate(entry) for entry in entries]
        except (ValueError, TypeError):
            raise HTTPException(422, "采集信息须为与上传文件同序、同数量的有效 JSON 列表。") from None
        inputs, total = [], 0
        for file, label in zip(files, labels):
            raw = await file.read(MAX_MESSAGE_BYTES + 1)
            total += len(raw)
            if len(raw) > MAX_MESSAGE_BYTES or total > MAX_RUN_BYTES:
                raise HTTPException(413, "单封须不超过 10 MiB，累计须不超过 50 MiB。")
            inputs.append(CaptureInput(**label.model_dump(), raw=raw))
        return await lab_call(ExperimentStore().compare, inputs)
    finally:
        for file in files:
            await file.close()


@router.get("/runs")
async def history(cursor: str | None = None):
    return await lab_call(ExperimentStore().history, cursor)


@router.get("/runs/{run_id}")
async def load(run_id: str) -> ExperimentManifest:
    return await lab_call(ExperimentStore().load, run_id)


@router.post("/runs/{run_id}/reproduce")
async def reproduce(run_id: str) -> ExperimentManifest:
    return await lab_call(ExperimentStore().reproduce, run_id)


@router.get("/runs/{run_id}/snapshots/{snapshot_id}/report")
async def report(run_id: str, snapshot_id: str):
    # FastAPI's generic JSON encoder does not apply the model's JSON mode.
    value = await lab_call(ExperimentStore().read_report, run_id, snapshot_id)
    return Response(value.model_dump_json(by_alias=True), media_type="application/json")


@router.get("/runs/{run_id}/snapshots/{snapshot_id}/message")
async def message(run_id: str, snapshot_id: str):
    data = await lab_call(ExperimentStore().read_message, run_id, snapshot_id)
    return Response(data, media_type="message/rfc822", headers={"Content-Disposition":f'attachment; filename="mailtrace-{run_id}-{snapshot_id}.eml"'})


@router.get("/runs/{run_id}/diffs/{diff_id}")
async def difference(run_id: str, diff_id: str) -> DiffReport:
    return await lab_call(ExperimentStore().read_diff, run_id, diff_id)


@router.get("/runs/{run_id}/export/{kind}")
async def export(run_id: str, kind: str):
    if kind not in {"zip", "csv"}:
        raise HTTPException(422, "导出格式须为 zip 或 csv。")
    store = ExperimentStore()
    data = await lab_call(store.export_zip if kind == "zip" else store.export_csv, run_id)
    return Response(data, media_type="application/zip" if kind == "zip" else "text/csv; charset=utf-8",
                    headers={"Content-Disposition":f'attachment; filename="mailtrace-{run_id}.{kind}"'})
