import re

from ..models.report import (
    ArcHeader, AuthAssertion, AuthProperty, AuthSummary, AuthenticationReport,
    DkimSignature, HeaderField, ParseDefect, ReceivedSpf,
)
from .tokens import balanced, first_value, remove_comments, split_top_level, unquote

KNOWN_RESULTS = {
    "spf": {"none", "neutral", "pass", "fail", "softfail", "temperror", "permerror"},
    "dkim": {"none", "pass", "fail", "neutral", "policy", "temperror", "permerror"},
    "dmarc": {"none", "pass", "fail", "temperror", "permerror"},
}
_VALUE = r'("(?:\\.|[^"\\])*"|[^\s;]+)'
_METHOD = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)\s*(?:/\s*\d+\s*)?=\s*' + _VALUE)
_PROPERTY = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)(?:\s*\.\s*([A-Za-z][A-Za-z0-9_-]*))?\s*=\s*' + _VALUE)


def parse_authentication(headers: list[HeaderField], defects: list[ParseDefect]) -> AuthenticationReport:
    report = AuthenticationReport()
    for field in headers:
        if not field.recognized:
            continue
        name = field.name.lower()
        value = field.value or ""
        if name == "authentication-results":
            if not balanced(value):
                defects.append(ParseDefect(code="UNBALANCED_HEADER_SYNTAX", message="认证结果的注释或引号未正确闭合。", header_id=field.id))
            segments = split_top_level(value)
            service_text = remove_comments(segments[0]).strip()
            service = first_value(service_text)
            for segment in segments[1:]:
                cleaned = remove_comments(segment).strip()
                if not cleaned or cleaned.lower() == "none":
                    continue
                method_match = _METHOD.match(cleaned)
                if not method_match:
                    defects.append(ParseDefect(code="INVALID_AUTH_CLAUSE", message="无法解析认证结果子句。", header_id=field.id))
                    continue
                method = method_match.group(1).split("/")[0].lower()
                result = unquote(method_match.group(2))
                assertion = AuthAssertion(
                    id=f"auth-{len(report.assertions) + 1:03}", header_id=field.id,
                    authserv_id=service, method=method, result=result,
                )
                remainder = cleaned[method_match.end():]
                position = 0
                while position < len(remainder):
                    if remainder[position].isspace():
                        position += 1
                        continue
                    assignment = _PROPERTY.match(remainder, position)
                    if assignment is None:
                        defects.append(ParseDefect(code="INVALID_AUTH_PROPERTY", message="无法解析认证结果属性。", header_id=field.id))
                        break
                    namespace, property_name, val = assignment.groups()
                    key = f"{namespace}.{property_name}" if property_name else namespace
                    if key.lower() == "reason":
                        assertion.reason = unquote(val)
                    else:
                        assertion.properties.append(AuthProperty(name=key, value=unquote(val)))
                    position = assignment.end()
                report.assertions.append(assertion)
                if method in KNOWN_RESULTS and result.lower() not in KNOWN_RESULTS[method]:
                    defects.append(ParseDefect(code="UNSUPPORTED_AUTH_RESULT", message="未知认证状态已原样保留。", header_id=field.id))
        elif name == "received-spf":
            tokens = remove_comments(value).split()
            report.received_spf.append(ReceivedSpf(header_id=field.id, result=tokens[0] if tokens else None))
        elif name == "dkim-signature":
            tags = {}
            for segment in split_top_level(value):
                key, equals, val = segment.partition("=")
                if equals:
                    key = key.strip().lower()
                    if key in tags:
                        defects.append(ParseDefect(code="DUPLICATE_DKIM_TAG", message="DKIM 标签重复，元信息仅展示首个值。", header_id=field.id))
                    tags.setdefault(key, val.strip())
            report.dkim_signatures.append(DkimSignature(header_id=field.id, domain=tags.get("d"), selector=tags.get("s"), algorithm=tags.get("a")))
        elif name in {"arc-seal", "arc-message-signature", "arc-authentication-results"}:
            report.arc_headers.append(ArcHeader(header_id=field.id, name=field.name))
    for method, known in KNOWN_RESULTS.items():
        assertions = [a for a in report.assertions if a.method == method]
        results = list(dict.fromkeys(a.result for a in assertions))
        normalized = {r.lower() for r in results}
        status = "unknown" if not results else "unrecognized" if not normalized.intersection(known) else "mixed" if len(normalized) > 1 else "reported"
        setattr(report.summary, method, AuthSummary(status=status, reported_results=results, assertion_ids=[a.id for a in assertions]))
    return report
