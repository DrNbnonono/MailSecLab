from ..models.report import Finding, MailHop


def comparison_key(host: str | None) -> str | None:
    return host.lower().rstrip(".") if host else None


def routing_loops(route: list[MailHop]) -> list[Finding]:
    findings = []
    seen_edges = {}
    path_nodes = []
    path_hops = []
    node_positions = {}
    for hop in route:
        a, b = comparison_key(hop.from_endpoint.hostname), comparison_key(hop.by.hostname)
        if not a or not b:
            path_nodes, path_hops, node_positions = [], [], {}
            continue
        edge = (a, b)
        evidence = None
        details = None
        if edge in seen_edges:
            evidence = [seen_edges[edge], hop]
            details = {"edge": list(edge)}
        seen_edges.setdefault(edge, hop)
        if not path_nodes or path_nodes[-1] != a:
            path_nodes, path_hops = [a], []
            node_positions = {a: 0}
        if b in node_positions and b != a:
            first = node_positions[b]
            evidence = path_hops[first:] + [hop]
            details = {"normalized_nodes": path_nodes[first:] + [b]}
            # A completed cycle starts a fresh connected segment, avoiding
            # repeatedly copying an ever-growing chain on repeated loops.
            path_nodes, path_hops, node_positions = [b], [], {b: 0}
        else:
            node_positions[b] = len(path_nodes)
            path_nodes.append(b)
            path_hops.append(hop)
        if evidence:
            findings.append(Finding(
                code="POSSIBLE_ROUTING_LOOP", severity="warning", message="Received 声明存在重复传输边或路径回返，仅为调查线索。",
                header_ids=[h.header_id for h in evidence], hop_ids=[h.id for h in evidence], details=details,
            ))
    return findings
