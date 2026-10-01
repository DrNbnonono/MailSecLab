import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  boundedBody,
  forwardAnalysis,
  MAX_REQUEST_BYTES,
} from "../src/lib/proxy";
import { POST } from "../src/app/api/analyze/route";

test("body bound checks actual bytes without Content-Length", async () => {
  const request = new Request("http://localhost/api/analyze", {
    method: "POST",
    body: new Uint8Array(MAX_REQUEST_BYTES + 1),
  });
  await assert.rejects(() => boundedBody(request), RangeError);
});

test("unsupported type is rejected and errors are not cached", async () => {
  const response = await forwardAnalysis(
    new Request("http://localhost", { method: "POST", body: "private mail" }),
    "http://127.0.0.1:1",
  );
  assert.equal(response.status, 415);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("unavailable backend produces a usable error without input echo", async () => {
  const response = await forwardAnalysis(
    new Request("http://localhost", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"raw_email":"SECRET"}',
    }),
    "http://127.0.0.1:1",
  );
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes("SECRET"));
});

test("actual Route Handler ignores Next.js context and proxies to configured server", async () => {
  const server = http.createServer((request, response) => {
    assert.equal(request.url, "/api/v1/analyze");
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      assert.equal(JSON.parse(body).raw_email, "Subject: test");
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end('{"schema_version":"0.1"}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const previous = process.env.MAILTRACE_API_URL;
  const address = server.address() as { port: number };
  process.env.MAILTRACE_API_URL = `http://127.0.0.1:${address.port}`;
  try {
    const request = new Request("http://localhost/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ raw_email: "Subject: test" }),
    });
    const handler = POST as unknown as (
      request: Request,
      context: object,
    ) => Promise<Response>;
    const result = await handler(request, { params: Promise.resolve({}) });
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { schema_version: "0.1" });
  } finally {
    if (previous === undefined) delete process.env.MAILTRACE_API_URL;
    else process.env.MAILTRACE_API_URL = previous;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
