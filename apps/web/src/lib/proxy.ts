export const MAX_REQUEST_BYTES = 12 * 1024 * 1024;

export async function boundedBody(request: Request): Promise<Uint8Array> {
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_REQUEST_BYTES))
    throw new RangeError("请求过大");
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_REQUEST_BYTES) {
        await reader.cancel();
        throw new RangeError("请求过大");
      }
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    body.set(part, offset);
    offset += part.byteLength;
  }
  return body;
}

export async function forwardAnalysis(
  request: Request,
  backend = process.env.MAILTRACE_API_URL || "http://127.0.0.1:8000",
): Promise<Response> {
  const contentType = request.headers.get("content-type") || "";
  const upload = contentType.toLowerCase().startsWith("multipart/form-data;");
  if (!upload && !/^application\/json(?:;|$)/i.test(contentType)) {
    return Response.json(
      { detail: "请提交 JSON 文本或 .eml 文件。" },
      { status: 415, headers: { "Cache-Control": "no-store" } },
    );
  }
  try {
    const body = await boundedBody(request);
    const url = new URL(`/api/v1/analyze${upload ? "/file" : ""}`, backend);
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": contentType },
      body: Buffer.from(body),
      cache: "no-store",
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(45_000)]),
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    const large = error instanceof RangeError;
    return Response.json(
      {
        detail: large
          ? "请求体超过 12 MiB 上限。"
          : "分析服务暂时不可用，请确认本地 API 已启动后重试。",
      },
      { status: large ? 413 : 502, headers: { "Cache-Control": "no-store" } },
    );
  }
}
