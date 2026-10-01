from email import policy
from email.parser import BytesHeaderParser

from ..analysis.timestamp import parse_timestamp
from ..models.report import HeaderField, MessageSummary, ParseDefect, SourceInfo
from .address import addresses, decode_text
from .raw import unfold


def parse_message(block: bytes, headers: list[HeaderField], source: SourceInfo) -> tuple[MessageSummary, list[ParseDefect]]:
    parsed = BytesHeaderParser(policy=policy.default).parsebytes(block)
    items = iter(parsed.raw_items())
    expected = next(items, None)
    for field in headers:
        if expected is None:
            break
        name, value = expected
        safe_value = value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
        if field.name is None or field.name.lower() != name.lower() or field.value != unfold(safe_value):
            # Python may skip an orphan continuation or Unix envelope line.
            # Only actual raw_items can mark a later candidate as recognized.
            continue
        field.recognized = True
        source.semantic_boundary_byte = field.end_byte
        expected = next(items, None)
    first_unrecognized = next((h.id for h in headers if not h.recognized), None)
    defects = [ParseDefect(code=f"PYTHON_{type(d).__name__}", message=str(d) or type(d).__name__, header_id=first_unrecognized) for d in parsed.defects]
    if expected is not None:
        defects.append(ParseDefect(code="HEADER_ALIGNMENT_FAILED", message="原始字段与 Python 语义视图无法对齐。", header_id=first_unrecognized))
    summary = MessageSummary()
    for field in headers:
        if not field.recognized:
            continue
        key = field.name.lower()
        if key in {"from", "to", "sender"}:
            getattr(summary, f"{key}_addresses").extend(addresses(field, defects))
        elif key == "subject" and summary.subject_header_id is None:
            summary.subject = decode_text(field.value or "")
            summary.subject_header_id = field.id
        elif key == "date" and summary.date_header_id is None:
            summary.date_raw = field.value
            summary.date_header_id = field.id
            summary.date, status = parse_timestamp(field.value)
            if status in {"invalid", "missing"}:
                defects.append(ParseDefect(code="INVALID_MESSAGE_DATE", message="Date 缺少可确定的时间或时区。", header_id=field.id))
        elif key == "return-path":
            summary.return_paths.append(field.value or "")
        elif key == "message-id":
            summary.message_ids.append(field.value or "")
    return summary, defects
