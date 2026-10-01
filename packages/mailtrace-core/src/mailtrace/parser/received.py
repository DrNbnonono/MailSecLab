import ipaddress
import re

from ..analysis.timestamp import parse_timestamp
from ..models.report import Endpoint, HeaderField, MailHop, ParseDefect
from .tokens import balanced, first_value, remove_comments, top_level_mask

_DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_CLAUSES = re.compile(r"(?<!\S)(from|by|with|id|for)(?=\s)", re.I)


def ip_scope(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if any(ip.version == n.version and ip in n for n in _DOCUMENTATION):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if any(ip.version == n.version and ip in n for n in _PRIVATE):
        return "private"
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return "reserved"
    return "public"


def endpoint(value: str | None, header_id: str, defects: list[ParseDefect]) -> Endpoint:
    if not value:
        return Endpoint()
    cleaned = remove_comments(value).strip()
    token = cleaned.split(maxsplit=1)[0] if cleaned else ""
    hostname = token if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", token) else None
    candidates = []
    seen = set()
    literals = re.findall(r"\[([^\[\]]+)\]", value)
    try:
        ipaddress.ip_address(token)
        literals.insert(0, token)
        hostname = None
    except ValueError:
        pass
    for literal in literals:
        literal = re.sub(r"^IPv6:", "", literal.strip(), flags=re.I)
        try:
            if "%" in literal:
                raise ValueError("Scope identifiers are not SMTP IP literals")
            address = str(ipaddress.ip_address(literal))
            if address not in seen:
                candidates.append(address)
                seen.add(address)
        except ValueError:
            defects.append(ParseDefect(code="INVALID_RECEIVED_IP", message="Received 中的地址字面量无法验证。", header_id=header_id))
    if len(candidates) == 1:
        return Endpoint(hostname=hostname, ip=candidates[0], ip_candidates=candidates, ip_scope=ip_scope(candidates[0]))
    return Endpoint(hostname=hostname, ip_candidates=candidates, ip_scope="ambiguous" if candidates else "unknown")


def parse_received(field: HeaderField, received_index: int, route_index: int, defects: list[ParseDefect]) -> MailHop:
    value = field.value or ""
    if not balanced(value):
        defects.append(ParseDefect(code="UNBALANCED_HEADER_SYNTAX", message="Received 注释、引号或地址字面量未正确闭合。", header_id=field.id))
    mask = top_level_mask(value)
    separator = mask.find(";")
    trace = value[:separator] if separator >= 0 else value
    timestamp_raw = value[separator + 1:].strip() or None if separator >= 0 else None
    timestamp, timezone_status = parse_timestamp(remove_comments(timestamp_raw).strip() if timestamp_raw else None)
    if timestamp_raw and timestamp is None:
        defects.append(ParseDefect(code="INVALID_RECEIVED_DATE", message="Received 时间或时区无法确定。", header_id=field.id))
    matches = list(_CLAUSES.finditer(top_level_mask(trace)))
    clauses = {}
    for position, match in enumerate(matches):
        stop = matches[position + 1].start() if position + 1 < len(matches) else len(trace)
        clauses.setdefault(match.group(1).lower(), trace[match.end():stop].strip())
    from_endpoint = endpoint(clauses.get("from"), field.id, defects)
    by = endpoint(clauses.get("by"), field.id, defects)

    def token(key: str) -> str | None:
        text = remove_comments(clauses.get(key, "")).strip()
        return first_value(text)

    recipient = remove_comments(clauses.get("for", "")).strip() or None
    if recipient:
        if recipient.startswith("<") and recipient.endswith(">"):
            recipient = recipient[1:-1]
    complete = bool(from_endpoint.hostname and by.hostname and timestamp)
    partial = bool(clauses or timestamp)
    return MailHop(
        id=f"hop-{route_index:03}", header_id=field.id, received_index=received_index, route_index=route_index,
        from_endpoint=from_endpoint, by=by, protocol=token("with"), queue_id=token("id"), recipient=recipient,
        timestamp=timestamp, timestamp_raw=timestamp_raw, timezone_status=timezone_status,
        parse_status="complete" if complete else "partial" if partial else "unparsed",
    )
