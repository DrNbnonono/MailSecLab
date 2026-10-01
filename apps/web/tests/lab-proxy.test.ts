import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { forwardLab } from "../src/lib/lab-proxy";

test("lab proxy rejects arbitrary paths and does not cache errors", async () => {
  const response = await forwardLab(
    new Request("http://localhost/api/lab/private"),
    ["private"],
  );
  assert.equal(response.status, 404);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("lab proxy preserves binary payload and attachment headers", async () => {
  const payload = Buffer.from([0, 255, 254, 13, 10]);
  let received: Buffer = Buffer.alloc(0);
  const server = createServer((request, response) => {
    const parts: Buffer[] = [];
    request.on("data", (chunk) => parts.push(chunk));
    request.on("end", () => {
      received = Buffer.concat(parts);
      response.writeHead(200, {
        "Content-Type": "application/zip",
        "Content-Disposition": "attachment; filename=experiment.zip",
      });
      response.end(payload);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const request = new Request("http://localhost/api/lab/compare", {
      method: "POST",
      headers: { "Content-Type": "multipart/form-data; boundary=example" },
      body: payload,
    });
    const response = await forwardLab(
      request,
      ["compare"],
      `http://127.0.0.1:${address.port}`,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(received, payload);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), payload);
    assert.ok(
      response.headers.get("content-disposition")?.includes("attachment"),
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("lab proxy rejects requests exceeding its separate budget", async () => {
  const response = await forwardLab(
    new Request("http://localhost/api/lab/forge", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(52 * 1024 * 1024 + 1),
      },
      body: "{}",
    }),
    ["forge"],
  );
  assert.equal(response.status, 413);
});
