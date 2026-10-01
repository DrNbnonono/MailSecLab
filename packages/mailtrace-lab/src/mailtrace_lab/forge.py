from dataclasses import dataclass
from datetime import timedelta, timezone
from email.utils import format_datetime
import random

from mailtrace import MailReport, analyze

from .models import CaseSpec, MAX_MESSAGE_BYTES, Measurements, SweepSpec


@dataclass(frozen=True)
class GeneratedSample:
    raw: bytes
    case: CaseSpec
    metrics: Measurements
    report: MailReport


def measure(raw: bytes, report: MailReport) -> Measurements:
    return Measurements(input_sha256=report.source.input_sha256, input_bytes=len(raw),
                        header_bytes=report.source.header_size_bytes,
                        max_line_bytes=max((len(line) for line in raw[:report.source.header_size_bytes].splitlines()), default=0),
                        candidate_received_count=report.route_summary.candidate_received_count,
                        recognized_received_count=len(report.route), field_count=len(report.headers))


def expand_cases(case: CaseSpec, sweep: SweepSpec | None = None) -> list[CaseSpec]:
    if sweep is None:
        return [case.model_copy(deep=True)]
    data = case.model_dump()
    return [CaseSpec.model_validate({**data, sweep.axis:value}) for value in sweep.values]


def _padding(size: int, newline: bytes, cap: int) -> bytes:
    prefix = b"X-Lab-Pad: "
    remaining = size - len(prefix) - len(newline)
    if remaining < 0 or cap < len(prefix):
        raise ValueError("头区目标不可实现；minimum padding field bytes: " + str(len(prefix) + len(newline)))
    parts = [prefix]
    available = cap - len(prefix)
    continuation_cost = len(newline) + 1
    while remaining > available:
        # A continuation must leave room for its newline and leading WSP.
        used = min(available, remaining - continuation_cost)
        if used < 0:
            raise ValueError("头区与行长组合不可实现；最小折行开销不足。")
        parts.extend([b"P" * used, newline, b" "])
        remaining -= used + continuation_cost
        available = cap - 1
    parts.extend([b"P" * remaining, newline])
    return b"".join(parts)


def forge_case(case: CaseSpec) -> GeneratedSample:
    newline = b"\r\n" if case.newline == "crlf" else b"\n"
    whitespace = "\t" if case.folding == "tab" else " "
    colon = " : " if case.pre_colon_space else ": "
    rng = random.Random(case.seed)
    queue_ids = [rng.getrandbits(32) for _ in range(case.received_count)]
    received = []
    for index in reversed(range(case.received_count)):
        if case.topology == "return":
            sender, receiver = ("relay-a.example", "relay-b.example") if index % 2 == 0 else ("relay-b.example", "relay-a.example")
        else:
            sender, receiver = f"relay-{index}.example", f"relay-{index + 1}.example"
        try:
            timestamp = case.base_time.astimezone(timezone.utc) + timedelta(seconds=index * (-1 if case.date_profile == "backwards" else 1))
        except (OverflowError, ValueError):
            raise ValueError("基准日期与 Received 数量导致时间溢出。") from None
        date = "not-a-date" if case.date_profile == "invalid" else format_datetime(timestamp)
        if case.date_profile == "unknown_timezone":
            date = date.replace("+0000", "-0000")
        separator = newline.decode() + whitespace if case.folding != "none" else " "
        value = f"from {sender}{separator}by {receiver} with ESMTP id lab-{queue_ids[index]:08x};{separator}{date}"
        received.append(("Received" + colon + value).encode("utf-8") + newline)
    fields = [(field.name + colon + field.value).encode("utf-8") + newline for field in case.headers]
    block = b"".join(received + fields if case.received_position == "first" else fields + received)
    baseline_max = max((len(line) for line in block.splitlines()), default=0)
    if case.max_line_bytes is not None:
        prefix = b"X-Lab-Line: "
        minimum = max(baseline_max, len(prefix))
        if case.max_line_bytes < minimum:
            raise ValueError(f"行长目标不可实现；minimum max_line_bytes: {minimum}")
        block += prefix + b"L" * (case.max_line_bytes - len(prefix)) + newline
    if case.header_bytes is not None:
        difference = case.header_bytes - len(block)
        overhead = len(b"X-Lab-Pad: ") + len(newline)
        if difference < 0 or 0 < difference < overhead:
            minimum = len(block) if difference < 0 else len(block) + overhead
            raise ValueError(f"头区目标不可实现；minimum header_bytes: {minimum}")
        if difference:
            block += _padding(difference, newline, case.max_line_bytes or max(78, baseline_max))
    raw = block + newline + b"MailTrace synthetic experiment." + newline
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("单封邮件超过 10 MiB 上限。")
    report = analyze(raw)
    metrics = measure(raw, report)
    if case.max_line_bytes is not None and metrics.max_line_bytes != case.max_line_bytes:
        raise ValueError("生成器未满足精确行长目标。")
    if case.header_bytes is not None and metrics.header_bytes != case.header_bytes:
        raise ValueError("生成器未满足精确头区大小目标。")
    return GeneratedSample(raw, case, metrics, report)
