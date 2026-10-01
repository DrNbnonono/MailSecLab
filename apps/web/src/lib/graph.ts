import type { Edge, Node } from "@xyflow/react";
import type { Endpoint, MailHop } from "./report";

export type HostData = {
  label: string;
  ip: string | null;
  scope: string;
  role: string;
  headerId: string;
  declarations: { headerId: string; role: string; ip: string | null }[];
  onSelect?: (id: string) => void;
};
export type TraceNode = Node<HostData>;
export type TraceEdge = Edge<{ headerId: string }>;

const key = (name: string | null) =>
  name ? name.toLowerCase().replace(/\.+$/, "") : null;

export function buildGraph(
  route: MailHop[],
  limit = 100,
): { nodes: TraceNode[]; edges: TraceEdge[]; omitted: number } {
  const nodes: TraceNode[] = [];
  const edges: TraceEdge[] = [];
  let previousBy: string | null = null;
  let previousTarget = "";
  function addNode(
    endpoint: Endpoint,
    id: string,
    role: string,
    headerId: string,
  ): string {
    nodes.push({
      id,
      type: "host",
      position: { x: nodes.length * 235, y: 80 },
      data: {
        label: endpoint.hostname || endpoint.ip || "未知节点",
        ip: endpoint.ip,
        scope: endpoint.ip_scope,
        role,
        headerId,
        declarations: [{ headerId, role, ip: endpoint.ip }],
      },
    });
    return id;
  }
  for (const hop of route.slice(0, limit)) {
    const fromKey = key(hop.from.hostname);
    const connected =
      previousBy !== null && fromKey !== null && previousBy === fromKey;
    const source = connected
      ? previousTarget
      : addNode(hop.from, `${hop.id}-from`, "来源声明", hop.header_id);
    if (connected) {
      const relay = nodes[nodes.length - 1].data;
      relay.role = "中继节点";
      relay.declarations.push({
        headerId: hop.header_id,
        role: "来源声明",
        ip: hop.from.ip,
      });
      if (hop.from.ip) {
        relay.ip = hop.from.ip;
        relay.scope = hop.from.ip_scope;
        relay.headerId = hop.header_id;
      }
    }
    const target = addNode(hop.by, `${hop.id}-by`, "接收节点", hop.header_id);
    edges.push({
      id: hop.id,
      source,
      target,
      type: "smoothstep",
      label: hop.protocol || "未知协议",
      data: { headerId: hop.header_id },
      style: { stroke: "#477c70", strokeWidth: 1.8 },
    });
    previousBy = key(hop.by.hostname);
    previousTarget = target;
  }
  return { nodes, edges, omitted: Math.max(0, route.length - limit) };
}
