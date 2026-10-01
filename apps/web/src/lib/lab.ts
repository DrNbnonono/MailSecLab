import type { MailReport } from "./report";

export interface HeaderSpec {
  name: string;
  value: string;
}
export interface CaseSpec {
  schema_version?: "0.1";
  name?: string;
  purpose?: string;
  seed?: number;
  base_time?: string;
  received_count: number;
  topology?: "chain" | "return";
  date_profile?: "valid" | "backwards" | "invalid" | "unknown_timezone";
  received_position?: "first" | "last";
  folding?: "none" | "space" | "tab";
  newline?: "crlf" | "lf";
  pre_colon_space?: boolean;
  headers?: HeaderSpec[];
  max_line_bytes?: number | null;
  header_bytes?: number | null;
}
export interface SweepSpec {
  axis: "received_count" | "max_line_bytes" | "header_bytes";
  values: number[];
}
export interface Measurements {
  input_sha256: string;
  input_bytes: number;
  header_bytes: number;
  max_line_bytes: number;
  candidate_received_count: number;
  recognized_received_count: number;
  field_count: number;
}
export interface Artifact {
  path: string;
  sha256: string;
  size_bytes: number;
}
export interface Snapshot {
  id: string;
  position: number;
  source: "generated" | "imported";
  label: string;
  capture_point: string;
  captured_at: string | null;
  mta: string | null;
  mta_version: string | null;
  config_digest: string | null;
  capture_gap: boolean;
  case: CaseSpec | null;
  metrics: Measurements;
  eml: Artifact;
  report: Artifact;
  smtp_result: null;
}
export interface StoredDiff {
  id: string;
  before_id: string;
  after_id: string;
  summary: Record<string, number>;
  report: Artifact;
}
export interface Experiment {
  schema_version: "0.1";
  id: string;
  kind: "generated_sample" | "parameter_sweep" | "capture_sequence";
  name: string;
  created_at: string;
  sweep: SweepSpec | null;
  derived_from: string | null;
  snapshots: Snapshot[];
  diffs: StoredDiff[];
  tool_versions: Record<string, string>;
}
export interface EvidenceRef {
  snapshot_id: string;
  header_id: string;
  name: string | null;
  start_byte: number;
  end_byte: number;
  start_line: number;
  end_line: number;
  sha256: string;
}
export interface Change {
  id: string;
  kind: string;
  before: EvidenceRef[];
  after: EvidenceRef[];
  notes: string[];
  received_changes: Record<string, { before: unknown; after: unknown }>;
}
export interface Difference {
  schema_version: "0.1";
  before_id: string;
  after_id: string;
  summary: Record<string, number>;
  changes: Change[];
  capture_gap: boolean;
  attribution: null;
  conclusion: string;
}
export interface HistoryItem {
  id: string;
  name: string;
  kind: string;
  created_at: string | null;
  snapshot_count: number | null;
  integrity: string;
}
export interface HistoryPage {
  items: HistoryItem[];
  next_cursor: string | null;
}
export const kindNames: Record<string, string> = {
  generated_sample: "生成样本",
  parameter_sweep: "参数扫描组",
  capture_sequence: "采集序列",
};
export const changeNames: Record<string, string> = {
  added: "新增",
  removed: "删除",
  value_changed: "值变化",
  format_changed: "格式变化",
  order_changed: "顺序变化",
  ambiguous: "对应不确定",
};
export const labUrl = (path: string) => `/api/lab/${path}`;
export async function labRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(labUrl(path), { ...init, cache: "no-store" });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("研究服务未返回有效报告，请查看历史或重试。");
  }
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string" ? data.detail : "研究请求失败。",
    );
  return data as T;
}
export type SnapshotReport = MailReport;
