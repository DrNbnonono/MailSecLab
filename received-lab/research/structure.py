"""Byte inventory, not an authoritative RFC parser or a mail repairer."""
import hashlib
import re

NAME = re.compile(rb'^[\x21-\x39\x3b-\x7e]+$')


def inspect(raw):
    boundary = raw.find(b'\r\n\r\n')
    block = raw[:boundary + 2] if boundary >= 0 else raw
    issues = []
    if boundary < 0:
        issues.append('missing-crlf-boundary')
    if re.search(rb'(?<!\r)\n', raw):
        issues.append('bare-lf')
    if re.search(rb'\r(?!\n)', raw):
        issues.append('bare-cr')
    fields, offset, max_line = [], 0, 0
    for line in block.split(b'\r\n'):
        if not line and offset >= len(block):
            break
        end = min(len(block), offset + len(line) + 2)
        max_line = max(max_line, len(line))
        if len(line) > 998:
            issues.append('physical-line-over-998')
        if line.startswith((b' ', b'\t')):
            if fields:
                fields[-1]['end'] = end
            else:
                issues.append('orphan-continuation')
        else:
            head, colon, _ = line.partition(b':')
            clean = head.rstrip(b' \t')
            syntax = 'modern' if colon and NAME.fullmatch(head) else 'obs' if colon and NAME.fullmatch(clean) else 'invalid'
            fields.append({'index': len(fields), 'start': offset, 'end': end,
                           'name': clean.decode('ascii', 'backslashreplace').lower(),
                           'name_hex': head.hex(), 'syntax': syntax})
        offset = end
    counts = {}
    for field in fields:
        counts[field['name']] = counts.get(field['name'], 0) + 1
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'boundary': boundary,
            'fields': fields, 'counts': counts, 'max_physical_line': max_line,
            'issues': sorted(set(issues)), 'inventory_only': True}


def field_bytes(raw, name):
    return [raw[f['start']:f['end']] for f in inspect(raw)['fields'] if f['name'] == name.lower()]


def require_modern(raw):
    info = inspect(raw)
    if info['issues'] or any(f['syntax'] != 'modern' for f in info['fields']):
        raise ValueError('base corpus is not structurally modern: ' + str(info['issues']))
    return info
