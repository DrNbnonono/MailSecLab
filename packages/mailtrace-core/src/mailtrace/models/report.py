from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AnalysisOptions(Model):
    chain_limit: int = Field(default=50, gt=0, strict=True)


class SourceInfo(Model):
    input_kind: Literal["bytes", "text_utf8"]
    input_sha256: str
    input_size_bytes: int
    header_sha256: str
    header_size_bytes: int
    header_base64: str
    has_body_separator: bool
    semantic_boundary_byte: int


class HeaderField(Model):
    id: str
    name: str | None
    raw: str
    value: str | None
    recognized: bool = False
    syntax: Literal["standard", "obsolete", "malformed"]
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


class Mailbox(Model):
    display_name: str | None = None
    address: str
    header_id: str


class MessageSummary(Model):
    subject: str | None = None
    from_addresses: list[Mailbox] = Field(default_factory=list)
    to_addresses: list[Mailbox] = Field(default_factory=list)
    sender_addresses: list[Mailbox] = Field(default_factory=list)
    return_paths: list[str] = Field(default_factory=list)
    message_ids: list[str] = Field(default_factory=list)
    date: datetime | None = None
    date_raw: str | None = None
    subject_header_id: str | None = None
    date_header_id: str | None = None


class Endpoint(Model):
    hostname: str | None = None
    ip: str | None = None
    ip_candidates: list[str] = Field(default_factory=list)
    ip_scope: Literal["public", "private", "loopback", "link_local", "documentation", "reserved", "ambiguous", "unknown"] = "unknown"


class MailHop(Model):
    id: str
    header_id: str
    received_index: int
    route_index: int
    from_endpoint: Endpoint = Field(default_factory=Endpoint, alias="from")
    by: Endpoint = Field(default_factory=Endpoint)
    protocol: str | None = None
    queue_id: str | None = None
    recipient: str | None = None
    timestamp: datetime | None = None
    timestamp_raw: str | None = None
    timezone_status: Literal["known", "utc_local_offset_unknown", "missing", "invalid"] = "missing"
    delay_seconds: float | None = None
    parse_status: Literal["complete", "partial", "unparsed"] = "unparsed"


class RouteSummary(Model):
    candidate_received_count: int
    recognized_received_count: int
    complete_hop_count: int
    total_observed_delay_seconds: float | None = None
    chain_limit: int


class AuthProperty(Model):
    name: str
    value: str


class AuthAssertion(Model):
    id: str
    header_id: str
    authserv_id: str | None = None
    method: str
    result: str
    properties: list[AuthProperty] = Field(default_factory=list)
    reason: str | None = None
    verified: Literal[False] = False
    trust: Literal["unassessed"] = "unassessed"


class AuthSummary(Model):
    status: Literal["unknown", "reported", "mixed", "unrecognized"] = "unknown"
    reported_results: list[str] = Field(default_factory=list)
    assertion_ids: list[str] = Field(default_factory=list)
    verified: Literal[False] = False


class AuthenticationSummary(Model):
    spf: AuthSummary = Field(default_factory=AuthSummary)
    dkim: AuthSummary = Field(default_factory=AuthSummary)
    dmarc: AuthSummary = Field(default_factory=AuthSummary)


class ReceivedSpf(Model):
    header_id: str
    result: str | None = None


class DkimSignature(Model):
    header_id: str
    domain: str | None = None
    selector: str | None = None
    algorithm: str | None = None
    verified: Literal[False] = False


class ArcHeader(Model):
    header_id: str
    name: str


class AuthenticationReport(Model):
    summary: AuthenticationSummary = Field(default_factory=AuthenticationSummary)
    assertions: list[AuthAssertion] = Field(default_factory=list)
    received_spf: list[ReceivedSpf] = Field(default_factory=list)
    dkim_signatures: list[DkimSignature] = Field(default_factory=list)
    arc_headers: list[ArcHeader] = Field(default_factory=list)


class Finding(Model):
    code: str
    severity: Literal["info", "warning"]
    message: str
    header_ids: list[str] = Field(default_factory=list)
    hop_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class ParseDefect(Model):
    code: str
    message: str
    header_id: str | None = None


class MailReport(Model):
    schema_version: Literal["0.1"] = "0.1"
    source: SourceInfo
    message: MessageSummary
    headers: list[HeaderField]
    route: list[MailHop]
    route_summary: RouteSummary
    authentication: AuthenticationReport
    warnings: list[Finding] = Field(default_factory=list)
    defects: list[ParseDefect] = Field(default_factory=list)
