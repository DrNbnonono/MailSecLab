"use client";
import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  useStore,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import { buildGraph, type TraceNode } from "@/lib/graph";
import { delay, utc, type MailHop } from "@/lib/report";
import { Icon } from "./icons";

function HostNode({ data }: NodeProps<TraceNode>) {
  return (
    <div className="host-node">
      <Handle type="target" position={Position.Left} />
      <div className="host-role">
        <span className="node-dot" />
        {data.role}
      </div>
      <strong title={data.label}>{data.label}</strong>
      <span className="host-ip">{data.ip || "IP 未声明"}</span>
      {data.declarations.length > 1 && (
        <div className="node-evidence">
          {data.declarations.map((item) => (
            <button
              key={`${item.headerId}-${item.role}`}
              title={`${item.role} · ${item.ip || "此字段未声明 IP"}`}
              onClick={(event) => {
                event.stopPropagation();
                data.onSelect?.(item.headerId);
              }}
            >
              {item.headerId} ↗
            </button>
          ))}
        </div>
      )}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes: NodeTypes = { host: HostNode };

function FitOnResize() {
  const { fitView } = useReactFlow();
  const ready = useNodesInitialized();
  const width = useStore((state) => state.width);
  const height = useStore((state) => state.height);
  useEffect(() => {
    if (ready && width && height) {
      void fitView({ padding: 0.2, minZoom: 0.15, maxZoom: 1 });
    }
  }, [fitView, ready, width, height]);
  return null;
}

export function TraceRoute({
  route,
  selected,
  onSelect,
}: {
  route: MailHop[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [view, setView] = useState<"graph" | "timeline">("graph");
  const [page, setPage] = useState(0);
  const graph = useMemo(() => buildGraph(route), [route]);
  const [measuredNodes, , onNodesChange] = useNodesState(graph.nodes);
  const nodes = measuredNodes.map((node) => ({
    ...node,
    data: { ...node.data, onSelect },
  }));
  const edges = useMemo(
    () =>
      graph.edges.map((edge) => ({
        ...edge,
        selected: edge.data?.headerId === selected,
        style: {
          ...edge.style,
          stroke: edge.data?.headerId === selected ? "#aa6b21" : "#477c70",
          strokeWidth: edge.data?.headerId === selected ? 3 : 1.8,
        },
        markerEnd: { type: "arrowclosed" as const, color: "#477c70" },
      })),
    [graph, selected],
  );
  return (
    <section className="panel route-panel">
      <div className="panel-heading">
        <div>
          <span className="section-eyebrow">02 / TRANSMISSION</span>
          <h2>
            传输路径 <span className="count">{route.length} hops</span>
          </h2>
        </div>
        <div className="segmented" aria-label="路径视图">
          <button
            aria-pressed={view === "graph"}
            onClick={() => setView("graph")}
          >
            <Icon name="route" />
            链路图
          </button>
          <button
            aria-pressed={view === "timeline"}
            onClick={() => setView("timeline")}
          >
            <Icon name="clock" />
            时间线
          </button>
        </div>
      </div>
      {!route.length ? (
        <div className="small-empty">
          <Icon name="route" size={28} />
          <p>没有可识别的 Received 字段</p>
          <span>仍可查看认证声明、解析缺陷与原始邮件头。</span>
        </div>
      ) : view === "graph" ? (
        <>
          <div
            className="graph-canvas"
            aria-label="邮件传输链路图"
            onKeyDownCapture={(event) => {
              if (event.key !== "Enter" && event.key !== " ") return;
              const target = event.target as HTMLElement;
              if (target.closest("button")) return;
              const element = target.closest(
                ".react-flow__node, .react-flow__edge",
              );
              const id = element?.getAttribute("data-id");
              const headerId =
                nodes.find((node) => node.id === id)?.data.headerId ||
                edges.find((edge) => edge.id === id)?.data?.headerId;
              if (headerId) {
                event.preventDefault();
                onSelect(headerId);
              }
            }}
          >
            <ReactFlow
              key={route.map((hop) => hop.id + hop.header_id).join("|")}
              nodes={nodes}
              onNodesChange={onNodesChange}
              edges={edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2, minZoom: 0.15, maxZoom: 1 }}
              minZoom={0.1}
              maxZoom={1.8}
              nodesDraggable={false}
              deleteKeyCode={null}
              nodesConnectable={false}
              edgesFocusable
              nodesFocusable
              onEdgeClick={(_, edge) =>
                edge.data?.headerId && onSelect(edge.data.headerId)
              }
              onNodeClick={(_, node) => onSelect(node.data.headerId)}
            >
              <Background color="#d7ddd7" gap={18} size={1} />
              <Controls showInteractive={false} />
              <FitOnResize />
            </ReactFlow>
          </div>
          <div className="graph-caption">
            <span>
              <span className="legend-line" />
              每条边对应一个 Received 声明
            </span>
            <span>点击边或节点，查看原始证据</span>
          </div>
          {graph.omitted > 0 && (
            <p className="limit-note">
              图中展示前 100 跳；另 {graph.omitted} 跳可在时间线或完整 JSON
              中核查。
            </p>
          )}
        </>
      ) : (
        <div className="timeline">
          {route.slice(page * 50, page * 50 + 50).map((hop) => (
            <button
              key={hop.id}
              className={`timeline-row ${selected === hop.header_id ? "active" : ""}`}
              onClick={() => onSelect(hop.header_id)}
            >
              <span className="hop-index">
                {String(hop.route_index).padStart(2, "0")}
              </span>
              <span className="timeline-main">
                <strong>
                  {hop.from.hostname || hop.from.ip || "未知节点"}
                  <span> → </span>
                  {hop.by.hostname || hop.by.ip || "未知节点"}
                </strong>
                <small>
                  {utc(hop.timestamp)} · {hop.protocol || "未知协议"} · UTC
                </small>
              </span>
              <span
                className={`delay ${hop.delay_seconds !== null && hop.delay_seconds < 0 ? "negative" : ""}`}
              >
                {delay(hop.delay_seconds)}
              </span>
            </button>
          ))}
          {route.length > 50 && (
            <div className="pagination">
              <button disabled={page === 0} onClick={() => setPage(page - 1)}>
                上一页
              </button>
              <span>
                {page + 1} / {Math.ceil(route.length / 50)}
              </span>
              <button
                disabled={(page + 1) * 50 >= route.length}
                onClick={() => setPage(page + 1)}
              >
                下一页
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
