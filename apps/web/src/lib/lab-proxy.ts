import { boundedBody } from "./proxy";

const responseError = (status: number, detail: string) =>
  Response.json(
    { detail },
    { status, headers: { "Cache-Control": "no-store" } },
  );
const validGet =
  /^(?:runs|runs\/[a-f0-9]{32}(?:\/snapshots\/snapshot-\d{3}\/(?:report|message)|\/diffs\/diff-\d{3}|\/export\/(?:zip|csv))?)$/;
const validPost = /^(?:forge|compare|runs\/[a-f0-9]{32}\/reproduce)$/;

export async function forwardLab(
  request: Request,
  segments: string[],
  backend = process.env.MAILTRACE_API_URL || "http://127.0.0.1:8000",
): Promise<Response> {
  const path = segments.join("/");
  if (
    !(
      request.method === "GET"
        ? validGet
        : request.method === "POST"
          ? validPost
          : /a^/
    ).test(path)
  )
    return responseError(404, "研究接口不存在。");
  const cursor = new URL(request.url).searchParams.get("cursor");
  if (cursor && !/^[a-f0-9]{32}$/.test(cursor))
    return responseError(422, "历史游标无效。");
  try {
    const body =
      request.method === "POST"
        ? await boundedBody(request, 52 * 1024 * 1024)
        : undefined;
    const url = new URL(`/api/v1/lab/${path}`, backend);
    if (path === "runs" && cursor) url.searchParams.set("cursor", cursor);
    const contentType = request.headers.get("content-type");
    const result = await fetch(url, {
      method: request.method,
      body: body ? Buffer.from(body) : undefined,
      headers: contentType ? { "Content-Type": contentType } : undefined,
      cache: "no-store",
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(120_000)]),
    });
    const headers = new Headers({ "Cache-Control": "no-store" });
    for (const name of ["content-type", "content-disposition"]) {
      const value = result.headers.get(name);
      if (value) headers.set(name, value);
    }
    return new Response(result.body, { status: result.status, headers });
  } catch (error) {
    return responseError(
      error instanceof RangeError ? 413 : 502,
      error instanceof RangeError
        ? "研究请求超过 52 MiB 上限。"
        : "研究服务不可用或等待超时，请查看实验历史后重试。",
    );
  }
}
