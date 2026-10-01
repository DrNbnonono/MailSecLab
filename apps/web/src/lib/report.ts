export interface Endpoint {
  hostname: string | null;
  ip: string | null;
  ip_candidates: string[];
  ip_scope: string;
}
export interface MailHop {
  id: string;
  header_id: string;
  received_index: number;
  route_index: number;
  from: Endpoint;
  by: Endpoint;
  protocol: string | null;
  queue_id: string | null;
  recipient: string | null;
  timestamp: string | null;
  timestamp_raw: string | null;
  timezone_status: string;
  delay_seconds: number | null;
  parse_status: string;
}
export interface HeaderField {
  id: string;
  name: string | null;
  raw: string;
  value: string | null;
  recognized: boolean;
  syntax: string;
  start_byte: number;
  end_byte: number;
  start_line: number;
  end_line: number;
}
export interface Finding {
  code: string;
  severity: "info" | "warning";
  message: string;
  header_ids: string[];
  hop_ids: string[];
  details: Record<string, unknown>;
}
export interface AuthAssertion {
  id: string;
  header_id: string;
  authserv_id: string | null;
  method: string;
  result: string;
  properties: { name: string; value: string }[];
  reason: string | null;
  verified: false;
  trust: string;
}
export interface AuthSummary {
  status: string;
  reported_results: string[];
  assertion_ids: string[];
  verified: false;
}
export interface MailReport {
  schema_version: "0.1";
  source: {
    input_kind: string;
    input_sha256: string;
    input_size_bytes: number;
    header_sha256: string;
    header_size_bytes: number;
    header_base64: string;
    has_body_separator: boolean;
    semantic_boundary_byte: number;
  };
  message: {
    subject: string | null;
    from_addresses: {
      display_name: string | null;
      address: string;
      header_id: string;
    }[];
    to_addresses: {
      display_name: string | null;
      address: string;
      header_id: string;
    }[];
    sender_addresses: {
      display_name: string | null;
      address: string;
      header_id: string;
    }[];
    return_paths: string[];
    message_ids: string[];
    date: string | null;
    date_raw: string | null;
    subject_header_id: string | null;
    date_header_id: string | null;
  };
  headers: HeaderField[];
  route: MailHop[];
  route_summary: {
    candidate_received_count: number;
    recognized_received_count: number;
    complete_hop_count: number;
    total_observed_delay_seconds: number | null;
    chain_limit: number;
  };
  authentication: {
    summary: Record<"spf" | "dkim" | "dmarc", AuthSummary>;
    assertions: AuthAssertion[];
    received_spf: { header_id: string; result: string | null }[];
    dkim_signatures: {
      header_id: string;
      domain: string | null;
      selector: string | null;
      algorithm: string | null;
      verified: false;
    }[];
    arc_headers: { header_id: string; name: string }[];
  };
  warnings: Finding[];
  defects: { code: string; message: string; header_id: string | null }[];
}

export function utc(value: string | null): string {
  if (!value) return "时间未知";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "时间未知"
    : date.toISOString().replace(".000Z", "Z").replace("T", " ");
}
export function delay(value: number | null): string {
  return value === null ? "—" : `${value >= 0 ? "+" : ""}${value} s`;
}
