import hashlib
import json
import re
import sys
import traceback
import dkim

raw = sys.stdin.buffer.read()
queries = []
mapping = json.load(open('/evidence/_state/dns.json'))


def dnsfunc(name, timeout=5):
    normalized = name.decode('ascii').rstrip('.').lower()
    record = mapping.get(normalized)
    queries.append({'name': normalized, 'found': record is not None})
    return record.encode() if record else None


out = {'status': 'none', 'input_sha256': hashlib.sha256(raw).hexdigest(), 'signatures': [], 'dns_queries': queries}
try:
    verifier = dkim.DKIM(raw)
    sig_count = sum(1 for name, _ in verifier.headers if name.lower() == b'dkim-signature')
    for index in range(sig_count):
        try:
            passed = verifier.verify(idx=index, dnsfunc=dnsfunc)
            out['signatures'].append({'status': 'pass' if passed else 'fail'})
        except dkim.DKIMException as exc:
            out['signatures'].append({'status': 'parse-error', 'error_type': type(exc).__name__, 'error': str(exc)})
    if out['signatures']:
        out['status'] = out['signatures'][0]['status']
except dkim.MessageFormatError as exc:
    out.update(status='parse-error', error=str(exc))
except Exception as exc:
    traceback.print_exc()
    out.update(status='tool-error', error_type=type(exc).__name__, error=str(exc))
print(json.dumps(out))
