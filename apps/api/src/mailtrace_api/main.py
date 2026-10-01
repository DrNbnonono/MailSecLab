from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from mailtrace import AnalysisOptions, MailReport, analyze
from starlette.concurrency import run_in_threadpool

from .limits import MAX_INPUT_BYTES, RequestBodyLimit
from .schemas import AnalyzeRequest

app = FastAPI(title="MailTrace API", version="0.4.0", description="本地邮件头调查接口。认证结果为头部声明，未主动验证。")
app.add_middleware(RequestBodyLimit)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, error: RequestValidationError):
    # FastAPI's default error includes input values; mail contents stay private.
    return JSONResponse({"detail": "输入无效：请检查邮件内容、文件和正整数链长阈值。"}, status_code=422)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": "0.4.0", "schema_version": "0.1"}


async def analyze_content(raw: str | bytes, chain_limit: int) -> MailReport:
    try:
        size = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw)
    except UnicodeError:
        raise HTTPException(status_code=422, detail="文本不是有效的 UTF-8 内容。") from None
    if size > MAX_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="邮件内容超过 10 MiB 上限。")
    if not raw or not raw.strip():
        raise HTTPException(status_code=422, detail="邮件内容为空。")
    try:
        return await run_in_threadpool(analyze, raw, options=AnalysisOptions(chain_limit=chain_limit))
    except (ValueError, UnicodeError):
        raise HTTPException(status_code=422, detail="邮件输入无法分析。") from None


@app.post("/api/v1/analyze", response_model=MailReport, response_model_by_alias=True)
async def analyze_text(payload: AnalyzeRequest):
    return await analyze_content(payload.raw_email, payload.chain_limit)


@app.post("/api/v1/analyze/file", response_model=MailReport, response_model_by_alias=True)
async def analyze_file(file: Annotated[UploadFile, File()], chain_limit: Annotated[int, Form(gt=0)] = 50):
    try:
        raw = await file.read(MAX_INPUT_BYTES + 1)
        return await analyze_content(raw, chain_limit)
    finally:
        await file.close()
