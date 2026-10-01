from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_MESSAGE_BYTES = 10 * 1024 * 1024
MAX_RUN_BYTES = 50 * 1024 * 1024
MAX_ITEMS = 20


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HeaderSpec(Model):
    name: str = Field(min_length=1, max_length=100)
    value: str = Field(max_length=100_000)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if any(ord(char) < 33 or ord(char) > 126 or char == ":" for char in value):
            raise ValueError("字段名须为不含冒号的 ASCII token。")
        if value.lower() == "received":
            raise ValueError("Received 使用专用数量参数，不在额外字段列表中重复定义。")
        return value

    @field_validator("value")
    @classmethod
    def single_value(cls, value):
        if "\r" in value or "\n" in value:
            raise ValueError("字段值不能包含换行；使用折行选项。")
        return value


def default_headers():
    return [HeaderSpec(name="From", value="Alice <alice@sender.example>"),
            HeaderSpec(name="To", value="Bob <bob@recipient.example>"),
            HeaderSpec(name="Subject", value="MailTrace synthetic experiment"),
            HeaderSpec(name="Date", value="Thu, 01 Oct 2026 12:00:00 +0000"),
            HeaderSpec(name="Message-ID", value="<baseline@sender.example>")]


class CaseSpec(Model):
    schema_version: Literal["0.1"] = "0.1"
    name: str = Field(default="Received baseline", min_length=1, max_length=200)
    purpose: str = Field(default="Received growth and header ambiguity", max_length=1000)
    seed: int = Field(default=0, ge=0, le=2**32 - 1, strict=True)
    base_time: datetime = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
    received_count: int = Field(default=2, ge=0, le=10_000, strict=True)
    topology: Literal["chain", "return"] = "chain"
    date_profile: Literal["valid", "backwards", "invalid", "unknown_timezone"] = "valid"
    received_position: Literal["first", "last"] = "first"
    folding: Literal["none", "space", "tab"] = "none"
    newline: Literal["crlf", "lf"] = "crlf"
    pre_colon_space: bool = Field(default=False, strict=True)
    headers: list[HeaderSpec] = Field(default_factory=default_headers, max_length=200)
    max_line_bytes: int | None = Field(default=None, ge=1, le=MAX_MESSAGE_BYTES, strict=True)
    header_bytes: int | None = Field(default=None, ge=1, le=MAX_MESSAGE_BYTES, strict=True)

    @field_validator("base_time")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("基准时间须包含明确时区。")
        return value


class SweepSpec(Model):
    axis: Literal["received_count", "max_line_bytes", "header_bytes"]
    values: list[int] = Field(min_length=1, max_length=MAX_ITEMS)

    @field_validator("values", mode="before")
    @classmethod
    def integer_values(cls, values):
        if not isinstance(values, list) or any(type(item) is not int for item in values):
            raise ValueError("扫描值须为整数列表。")
        return values


class Measurements(Model):
    input_sha256: str
    input_bytes: int
    header_bytes: int
    max_line_bytes: int
    candidate_received_count: int
    recognized_received_count: int
    field_count: int


class EvidenceRef(Model):
    snapshot_id: str
    header_id: str
    name: str | None
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    sha256: str


class HeaderChange(Model):
    id: str
    kind: Literal["added", "removed", "value_changed", "format_changed", "order_changed", "ambiguous"]
    before: list[EvidenceRef] = Field(default_factory=list)
    after: list[EvidenceRef] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    received_changes: dict[str, dict] = Field(default_factory=dict)


class DiffReport(Model):
    schema_version: Literal["0.1"] = "0.1"
    before_id: str
    after_id: str
    summary: dict[str, int]
    changes: list[HeaderChange]
    capture_gap: bool = False
    attribution: None = None
    conclusion: str = "变化发生于这两处采集之间；不能仅凭差分确定修改者。"


class CaptureMetadata(Model):
    label: str = Field(default="未标记采集点", min_length=1, max_length=200)
    capture_point: Literal["submitted", "ingress", "egress", "delivered", "unknown"] = "unknown"
    captured_at: datetime | None = None
    mta: str | None = Field(default=None, max_length=200)
    mta_version: str | None = Field(default=None, max_length=200)
    config_digest: str | None = Field(default=None, max_length=200)
    capture_gap: bool = Field(default=False, strict=True)

    @field_validator("captured_at")
    @classmethod
    def aware_capture_time(cls, value):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("采集时间须包含明确时区；未知时留空。")
        return value


class CaptureInput(CaptureMetadata):
    raw: bytes


class Artifact(Model):
    path: str
    sha256: str
    size_bytes: int


class Snapshot(CaptureMetadata):
    id: str
    position: int
    source: Literal["generated", "imported"]
    metrics: Measurements
    case: CaseSpec | None = None
    eml: Artifact
    report: Artifact
    case_artifact: Artifact | None = None
    smtp_result: None = None
    mta_log: None = None
    delivery_result: None = None


class StoredDiff(Model):
    id: str
    before_id: str
    after_id: str
    summary: dict[str, int]
    report: Artifact


class ExperimentManifest(Model):
    schema_version: Literal["0.1"] = "0.1"
    id: str
    kind: Literal["generated_sample", "parameter_sweep", "capture_sequence"]
    name: str
    created_at: datetime
    tool_versions: dict[str, str] = Field(default_factory=lambda: {"mailtrace-lab":"0.1.0", "mailtrace-core":"0.1.0"})
    sweep: SweepSpec | None = None
    derived_from: str | None = None
    snapshots: list[Snapshot] = Field(min_length=1, max_length=MAX_ITEMS)
    diffs: list[StoredDiff] = Field(default_factory=list)
