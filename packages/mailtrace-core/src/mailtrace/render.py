import unicodedata

from .models.report import MailReport


def safe_text(value: object) -> str:
    text = str(value)
    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C") or c in "\u2028\u2029" else c for c in text)


def render(report: MailReport) -> str:
    message = report.message
    lines = ["MailTrace 0.1 — 离线邮件头分析", "Message"]
    for key, value in (
        ("Subject", message.subject), ("From", ", ".join(a.address for a in message.from_addresses)),
        ("To", ", ".join(a.address for a in message.to_addresses)), ("Message-ID", ", ".join(message.message_ids)),
    ):
        lines.append(f"  {key:<12} {safe_text(value) if value else 'unknown'}")
    lines.append("Authentication — 邮件头声明，MailTrace 未主动验证")
    for method in ("spf", "dkim", "dmarc"):
        summary = getattr(report.authentication.summary, method)
        results = ", ".join(summary.reported_results)
        services = list(dict.fromkeys(a.authserv_id or "unknown" for a in report.authentication.assertions if a.method == method))
        text = summary.status + (f": {results}" if results else "") + (f" [{', '.join(services)}]" if services else "")
        lines.append(f"  {method.upper():<12} {safe_text(text)}")
    lines.append("Route — 字段声明的传输顺序")
    for hop in report.route:
        a = hop.from_endpoint.hostname or hop.from_endpoint.ip or "未知节点"
        b = hop.by.hostname or hop.by.ip or "未知节点"
        lines.append(f"  [{hop.route_index}] {safe_text(a)} → {safe_text(b)}    {safe_text(hop.protocol or 'unknown')}  ({hop.header_id})")
        time = hop.timestamp.isoformat().replace("+00:00", "Z") if hop.timestamp else "时间未知"
        delay = f"    {hop.delay_seconds:+g}s" if hop.delay_seconds is not None else ""
        lines.append(f"      {time}{delay}")
    if not report.route:
        lines.append("  无可识别的 Received 字段")
    lines.append("Warnings")
    for item in report.warnings:
        lines.append(f"  [{item.severity}] {item.code}  {safe_text(item.message)}  [{', '.join(item.header_ids)}]")
    if not report.warnings:
        lines.append("  未发现已配置规则的异常；不表示来源已验证")
    if report.defects:
        lines.append("Parser defects")
        for item in report.defects:
            lines.append(f"  {item.code}  {safe_text(item.message)}")
    return "\n".join(lines)
