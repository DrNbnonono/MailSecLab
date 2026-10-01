from ..models.report import Finding, HeaderField, MailHop, RouteSummary, SourceInfo
from .loop import comparison_key, routing_loops


def findings(headers: list[HeaderField], route: list[MailHop], summary: RouteSummary, source: SourceInfo) -> list[Finding]:
    output = []
    unrecognized = [h for h in headers if not h.recognized]
    if unrecognized:
        output.append(Finding(
            code="HEADER_PARSER_DISAGREEMENT", severity="warning", message="部分物理候选字段未被 Python 邮件解析器识别。",
            header_ids=[h.id for h in unrecognized], details={"candidate_count": len(headers), "recognized_count": sum(h.recognized for h in headers), "semantic_boundary_byte": source.semantic_boundary_byte},
        ))
    groups = {}
    for field in headers:
        if field.recognized and field.name.lower() in {"from", "date", "subject", "message-id"}:
            groups.setdefault(field.name.lower(), []).append(field)
    for key, fields in groups.items():
        if len(fields) > 1:
            output.append(Finding(code="DUPLICATE_SINGLETON", severity="warning", message=f"{key} 存在多个字段实例。", header_ids=[h.id for h in fields], details={"field_name": key, "count": len(fields)}))
    for hop in route:
        if hop.parse_status != "complete":
            missing = [key for key, value in (("from", hop.from_endpoint.hostname), ("by", hop.by.hostname), ("timestamp", hop.timestamp)) if value is None]
            output.append(Finding(code="RECEIVED_PARTIAL", severity="info", message="Received 只能部分解析，原始字段已保留。", header_ids=[hop.header_id], hop_ids=[hop.id], details={"missing": missing}))
    if summary.recognized_received_count > summary.chain_limit:
        output.append(Finding(code="LONG_RECEIVED_CHAIN", severity="warning", message="Received 数量超过本次分析的启发式阈值。", details={"count": summary.recognized_received_count, "limit": summary.chain_limit}))
    for hop in route:
        for endpoint in (hop.from_endpoint, hop.by):
            if endpoint.ip_scope == "private":
                output.append(Finding(code="PRIVATE_IP_EXPOSED", severity="info", message=f"Received 声明中出现私有地址 {endpoint.ip}。", header_ids=[hop.header_id], hop_ids=[hop.id], details={"ip": endpoint.ip, "scope": "private"}))
    for previous, current in zip(route, route[1:]):
        if current.delay_seconds is not None and current.delay_seconds < 0:
            output.append(Finding(code="TIMESTAMP_REVERSED", severity="warning", message="相邻 Received 时间倒退，可能存在时钟或字段异常。", header_ids=[previous.header_id, current.header_id], hop_ids=[previous.id, current.id], details={"previous_time": previous.timestamp.isoformat(), "current_time": current.timestamp.isoformat(), "delay_seconds": current.delay_seconds}))
    for previous, current in zip(route, route[1:]):
        a, b = comparison_key(previous.by.hostname), comparison_key(current.from_endpoint.hostname)
        if a and b and a != b:
            output.append(Finding(code="ROUTE_DISCONTINUITY", severity="info", message="相邻跳的主机声明不衔接，可能涉及别名或不完整字段。", header_ids=[previous.header_id, current.header_id], hop_ids=[previous.id, current.id], details={"previous_by": previous.by.hostname, "next_from": current.from_endpoint.hostname}))
    output.extend(routing_loops(route))
    # Do not duplicate the same rule/evidence, e.g. a private IP in both endpoints.
    unique = {}
    for item in output:
        key = (item.code, tuple(item.header_ids), tuple(item.hop_ids), str(item.details))
        unique.setdefault(key, item)
    return list(unique.values())
