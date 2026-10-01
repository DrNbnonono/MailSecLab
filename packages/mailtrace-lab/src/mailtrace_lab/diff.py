from bisect import bisect_left
from collections import defaultdict
import base64
import hashlib
import re

from mailtrace import MailReport, analyze

from .models import DiffReport, EvidenceRef, HeaderChange, MAX_MESSAGE_BYTES


def _stable_pairs(pairs):
    """Patience anchors: O(n log n), without a quadratic edit matrix."""
    ordered = sorted(pairs)
    tails, tail_indices, parents = [], [], []
    for index, (_, target) in enumerate(ordered):
        place = bisect_left(tails, target)
        parents.append(tail_indices[place - 1] if place else -1)
        if place == len(tails):
            tails.append(target)
            tail_indices.append(index)
        else:
            tails[place], tail_indices[place] = target, index
    result = []
    pointer = tail_indices[-1] if tail_indices else -1
    while pointer >= 0:
        result.append(ordered[pointer])
        pointer = parents[pointer]
    return list(reversed(result))


def compare_headers(before: bytes, after: bytes, *, before_id="snapshot-001", after_id="snapshot-002",
                    capture_gap=False, before_report: MailReport | None = None, after_report: MailReport | None = None) -> DiffReport:
    if not before or not after or max(len(before), len(after)) > MAX_MESSAGE_BYTES:
        raise ValueError("比较需要两份非空、各不超过 10 MiB 的原始邮件。")
    reports = [before_report or analyze(before), after_report or analyze(after)]
    for raw, report in zip((before, after), reports):
        if report.source.input_sha256 != hashlib.sha256(raw).hexdigest() or report.source.input_size_bytes != len(raw):
            raise ValueError("缓存报告与原始邮件不匹配，不能作为差分证据。")
    hop_views = [{hop.header_id:hop.model_dump(mode="json", by_alias=True) for hop in report.route} for report in reports]
    headers = [report.headers for report in reports]
    blocks = [raw[:report.source.header_size_bytes] for raw, report in zip((before, after), reports)]
    if any(block != base64.b64decode(report.source.header_base64) for block, report in zip(blocks, reports)):
        raise ValueError("缓存报告头区与原始邮件不匹配。")
    chunks = [[block[field.start_byte:field.end_byte] for field in fields] for block, fields in zip(blocks, headers)]
    ids = [before_id, after_id]
    used = [set(), set()]
    matches = []
    changes = []

    def evidence(side, index):
        field = headers[side][index]
        return EvidenceRef(snapshot_id=ids[side], header_id=field.id, name=field.name,
                           start_byte=field.start_byte, end_byte=field.end_byte,
                           start_line=field.start_line, end_line=field.end_line,
                           sha256=hashlib.sha256(chunks[side][index]).hexdigest())

    def emit(kind, left, right, notes=()):
        change = HeaderChange(id=f"change-{len(changes)+1:03}", kind=kind,
                              before=[evidence(0, i) for i in left], after=[evidence(1, i) for i in right], notes=list(notes))
        if len(left) == len(right) == 1:
            first, second = headers[0][left[0]], headers[1][right[0]]
            if first.recognized != second.recognized:
                change.notes.append("Python 语义识别状态发生变化。")
            if first.name and first.name.lower() == "received":
                hops = [view.get(field.id) for view, field in zip(hop_views, (first, second))]
                for key in ("from", "by", "protocol", "queue_id", "recipient", "timestamp", "timestamp_raw", "parse_status"):
                    values = [hop.get(key) if hop else None for hop in hops]
                    if values[0] != values[1]:
                        change.received_changes[key] = {"before":values[0], "after":values[1]}
        changes.append(change)

    def grouping(side, key):
        groups = defaultdict(list)
        for i, field in enumerate(headers[side]):
            if i not in used[side]:
                value = key(side, i, field)
                if value is not None:
                    groups[value].append(i)
        return groups

    def pair_groups(key, kind):
        left, right = grouping(0, key), grouping(1, key)
        for token in left.keys() & right.keys():
            litems, ritems = left[token], right[token]
            # Iteration is sorted below before assigning final change IDs.
            if len(litems) == len(ritems) == 1:
                matches.append((litems[0], ritems[0]))
                if kind != "exact":
                    emit(kind, litems, ritems, ["仅按字段名大小写、外层 WSP、换行及明确折行规则比较。"])
            else:
                emit("ambiguous", litems, ritems, ["重复等价字段无法唯一对应；保留全部候选与数量变化。"])
            used[0].update(litems)
            used[1].update(ritems)

    pair_groups(lambda side, index, field: chunks[side][index], "exact")

    def canonical(side, index, field):
        if field.syntax != "standard":
            return None
        name, _, value = chunks[side][index].partition(b":")
        # Keep internal WSP intact; LF normalization is a recorded lexical rule,
        # not a claim of RFC validity or address/signature equivalence.
        value = value.replace(b"\r\n", b"\n")
        value = re.sub(rb"\n(?=[ \t])", b"", value).rstrip(b"\n").strip(b" \t")
        return name.lower(), value

    pair_groups(canonical, "format_changed")
    anchors = _stable_pairs(matches)
    if len(anchors) != len(matches):
        ordered = sorted(matches)
        emit("order_changed", [pair[0] for pair in ordered], [pair[1] for pair in sorted(matches, key=lambda pair:pair[1])],
             ["共同字段的相对顺序改变；不能唯一确定是哪一个字段被移动。"])
    boundaries = [(-1, -1), *anchors, (len(headers[0]), len(headers[1]))]
    for (left_start, right_start), (left_end, right_end) in zip(boundaries, boundaries[1:]):
        groups = [defaultdict(list), defaultdict(list)]
        for side, start, end in ((0, left_start, left_end), (1, right_start, right_end)):
            for i in range(start + 1, end):
                if i not in used[side]:
                    field = headers[side][i]
                    if field.name is not None:
                        groups[side][field.name.lower()].append(i)
        for key in groups[0].keys() & groups[1].keys():
            left, right = groups[0][key], groups[1][key]
            if len(left) == len(right) == 1:
                notes = ["稳定锚点区间内唯一同名候选对应。"]
                lraw, rraw = chunks[0][left[0]], chunks[1][right[0]]
                if lraw.rstrip(b"\r\n").startswith(rraw.rstrip(b"\r\n")) and len(rraw) < len(lraw):
                    notes.append("存在前缀缩短迹象；未确认截断原因。")
                emit("value_changed", left, right, notes)
            else:
                emit("ambiguous", left, right, ["同名字段存在多种对应关系，不强行推断改写。"])
            used[0].update(left)
            used[1].update(right)
    for side, kind in ((0, "removed"), (1, "added")):
        for i in range(len(headers[side])):
            if i not in used[side]:
                emit(kind, [i] if side == 0 else [], [i] if side == 1 else [])
    changes.sort(key=lambda item: (min((ref.start_byte for ref in item.after), default=10**20),
                                   min((ref.start_byte for ref in item.before), default=10**20), item.kind))
    summary = dict.fromkeys(("added", "removed", "value_changed", "format_changed", "order_changed", "ambiguous"), 0)
    for i, change in enumerate(changes, 1):
        change.id = f"change-{i:03}"
        summary[change.kind] += 1
        if change.kind == "ambiguous":
            summary["added"] += max(0, len(change.after) - len(change.before))
            summary["removed"] += max(0, len(change.before) - len(change.after))
    return DiffReport(before_id=before_id, after_id=after_id, summary=summary, changes=changes, capture_gap=capture_gap)
