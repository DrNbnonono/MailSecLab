import test from "node:test";
import assert from "node:assert/strict";
import { buildGraph } from "../src/lib/graph";
import type { MailHop } from "../src/lib/report";

function hop(index: number, from: string | null, by: string | null): MailHop {
  return {
    id: `hop-${index}`,
    header_id: `header-${index}`,
    route_index: index,
    received_index: index,
    from: { hostname: from, ip: null, ip_candidates: [], ip_scope: "unknown" },
    by: { hostname: by, ip: null, ip_candidates: [], ip_scope: "unknown" },
    protocol: "ESMTP",
    queue_id: null,
    recipient: null,
    timestamp: null,
    timestamp_raw: null,
    timezone_status: "missing",
    delay_seconds: null,
    parse_status: "partial",
  };
}

test("connected hops share a relay and edges retain evidence IDs", () => {
  const graph = buildGraph([
    hop(1, "a.example", "b.example"),
    hop(2, "B.EXAMPLE.", "c.example"),
  ]);
  assert.equal(graph.nodes.length, 3);
  assert.equal(graph.edges.length, 2);
  assert.equal(graph.edges[0].id, "hop-1");
  assert.equal(graph.edges[0].data?.headerId, "header-1");
  assert.equal(graph.edges[0].target, graph.edges[1].source);
});

test("discontinuity is not drawn as an observed connection", () => {
  const graph = buildGraph([
    hop(1, "a.example", "b.example"),
    hop(2, "d.example", "e.example"),
  ]);
  assert.equal(graph.nodes.length, 4);
  assert.equal(graph.edges.length, 2);
  assert.notEqual(graph.edges[0].target, graph.edges[1].source);
});

test("shared relay retains both declarations and ties displayed IP to its source", () => {
  const first = hop(1, "a.example", "b.example");
  const second = hop(2, "b.example", "c.example");
  second.from.ip = "192.0.2.25";
  second.from.ip_scope = "documentation";
  const relay = buildGraph([first, second]).nodes[1].data;
  assert.equal(relay.ip, "192.0.2.25");
  assert.equal(relay.headerId, "header-2");
  assert.deepEqual(
    relay.declarations.map((item) => item.headerId),
    ["header-1", "header-2"],
  );
  assert.equal(relay.declarations[0].ip, null);
  assert.equal(relay.declarations[1].ip, "192.0.2.25");
});

test("unknown nodes never merge just because both names are missing", () => {
  const graph = buildGraph([
    hop(1, "a.example", null),
    hop(2, null, "c.example"),
  ]);
  assert.equal(graph.nodes.length, 4);
});

test("return path retains separate occurrences of the same hostname", () => {
  const graph = buildGraph([
    hop(1, "a.example", "b.example"),
    hop(2, "b.example", "a.example"),
  ]);
  assert.equal(graph.nodes.length, 3);
  assert.notEqual(graph.nodes[0].id, graph.nodes[2].id);
});

test("render cap does not modify the complete route", () => {
  const route = Array.from({ length: 105 }, (_, i) =>
    hop(i + 1, `relay-${i}.example`, `relay-${i + 1}.example`),
  );
  const graph = buildGraph(route);
  assert.equal(graph.edges.length, 100);
  assert.equal(graph.omitted, 5);
  assert.equal(route.length, 105);
});
