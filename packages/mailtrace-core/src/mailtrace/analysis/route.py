from ..models.report import HeaderField, MailHop, ParseDefect, RouteSummary
from ..parser.received import parse_received
from .timestamp import assign_delays


def build_route(headers: list[HeaderField], chain_limit: int, defects: list[ParseDefect]) -> tuple[list[MailHop], RouteSummary]:
    candidates = [h for h in headers if h.name and h.name.lower() == "received"]
    received = [h for h in candidates if h.recognized]
    total = len(received)
    route = [parse_received(field, total - position + 1, position, defects) for position, field in enumerate(reversed(received), 1)]
    return route, RouteSummary(
        candidate_received_count=len(candidates), recognized_received_count=total,
        complete_hop_count=sum(h.parse_status == "complete" for h in route),
        total_observed_delay_seconds=assign_delays(route), chain_limit=chain_limit,
    )
