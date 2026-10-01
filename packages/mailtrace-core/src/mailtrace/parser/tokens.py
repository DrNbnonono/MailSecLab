"""Linear scanners that respect nested comments and quoted strings."""
import re


def _scan_mask(value: str) -> tuple[str, bool]:
    depth = 0
    quoted = False
    bracket = False
    escaped = False
    invalid_close = False
    output = []
    for char in value:
        hidden = depth > 0 or quoted or bracket
        if escaped:
            escaped = False
            output.append(" ")
            continue
        if char == "\\" and (depth or quoted):
            escaped = True
        elif char == '"' and not depth and not bracket:
            quoted = not quoted
        elif char == "(" and not quoted and not bracket:
            depth += 1
        elif char == ")" and depth and not quoted and not bracket:
            depth -= 1
        elif char == "[" and not depth and not quoted:
            bracket = True
        elif char == "]" and bracket:
            bracket = False
        elif char in ")]" and not hidden:
            invalid_close = True
        output.append(" " if hidden or depth or quoted or bracket or char in '()"[]' else char)
    return "".join(output), not (depth or quoted or bracket or escaped or invalid_close)


def top_level_mask(value: str) -> str:
    return _scan_mask(value)[0]


def balanced(value: str) -> bool:
    return _scan_mask(value)[1]


def split_top_level(value: str, delimiter: str = ";") -> list[str]:
    mask = top_level_mask(value)
    positions = [i for i, char in enumerate(mask) if char == delimiter]
    result = []
    start = 0
    for position in positions:
        result.append(value[start:position])
        start = position + 1
    result.append(value[start:])
    return result


def remove_comments(value: str) -> str:
    depth = 0
    quoted = False
    escaped = False
    output = []
    for char in value:
        if escaped:
            if not depth:
                output.append(char)
            escaped = False
            continue
        if char == "\\" and (depth or quoted):
            escaped = True
            if not depth:
                output.append(char)
        elif char == '"' and not depth:
            quoted = not quoted
            output.append(char)
        elif char == "(" and not quoted:
            if not depth:
                output.append(" ")
            depth += 1
        elif char == ")" and depth and not quoted:
            depth -= 1
        elif not depth:
            output.append(char)
    return "".join(output)


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def first_value(value: str) -> str | None:
    match = re.match(r'"(?:\\.|[^"\\])*"|[^\s"]+', value.strip())
    return unquote(match.group()) if match else None
