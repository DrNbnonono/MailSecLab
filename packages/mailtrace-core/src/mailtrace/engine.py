from .analysis.anomalies import findings
from .analysis.route import build_route
from .models.report import AnalysisOptions, MailReport
from .parser.auth_results import parse_authentication
from .parser.message import parse_message
from .parser.raw import scan


def analyze(raw_email: bytes | str, *, options: AnalysisOptions | None = None) -> MailReport:
    """Analyze header declarations offline, without authenticating their origin."""
    if not isinstance(raw_email, (bytes, str)):
        raise TypeError("raw_email must be bytes or str")
    raw = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
    if not raw:
        raise ValueError("邮件输入为空。")
    if options is not None and not isinstance(options, AnalysisOptions):
        raise TypeError("options must be AnalysisOptions")
    options = options or AnalysisOptions()
    source, headers = scan(raw, "text_utf8" if isinstance(raw_email, str) else "bytes")
    message, defects = parse_message(raw[:source.header_size_bytes], headers, source)
    route, summary = build_route(headers, options.chain_limit, defects)
    authentication = parse_authentication(headers, defects)
    return MailReport(source=source, message=message, headers=headers, route=route, route_summary=summary,
                      authentication=authentication, warnings=findings(headers, route, summary, source), defects=defects)
