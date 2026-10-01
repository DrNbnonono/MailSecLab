from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re

from ..models.report import MailHop
from ..parser.tokens import remove_comments

_ZONE = re.compile(r"\d{1,2}:\d{2}(?::\d{2})?\s+([+-]\d{4}|[A-Za-z]+)\s*$")
_KNOWN = {"UT", "UTC", "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT"}


def parse_timestamp(value: str | None) -> tuple[datetime | None, str]:
    if not value:
        return None, "missing"
    value = remove_comments(value).strip()
    zone = _ZONE.search(value)
    try:
        parsed = parsedate_to_datetime(value)
    except (ValueError, TypeError, OverflowError):
        return None, "invalid"
    if zone is None:
        return None, "missing"
    token = zone.group(1)
    if token == "-0000":
        return parsed.replace(tzinfo=timezone.utc), "utc_local_offset_unknown"
    if token.isalpha() and token.upper() not in _KNOWN:
        return None, "invalid"
    if parsed.tzinfo is None:
        return None, "invalid"
    try:
        return parsed.astimezone(timezone.utc), "known"
    except (ValueError, OverflowError):
        return None, "invalid"


def assign_delays(route: list[MailHop]) -> float | None:
    for previous, current in zip(route, route[1:]):
        if previous.timestamp is not None and current.timestamp is not None:
            current.delay_seconds = (current.timestamp - previous.timestamp).total_seconds()
    if len(route) >= 2 and all(h.timestamp is not None for h in route):
        return (route[-1].timestamp - route[0].timestamp).total_seconds()
    return None
