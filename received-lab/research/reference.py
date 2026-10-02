"""Independent RSA-SHA256 DKIM reference for controlled modern IMF cases.

It rejects malformed header structure rather than choosing a lenient parser.
It is a diagnostic reference, not a general-purpose production verifier.
"""
import base64
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from . import structure


def lookup_key(name, mapping):
    if isinstance(name, bytes):
        name = name.decode('ascii')
    return mapping.get(name.rstrip('.').lower())


def select(raw, names, top_down=False):
    """RFC 6376 §3.5 walks bottom-up. top_down is only a contrasting oracle."""
    fields = list(structure.inspect(raw)['fields'])
    sequence = fields if top_down else list(reversed(fields))
    used, chosen = set(), []
    for name in names:
        match = next((f for f in sequence if f['name'] == name.lower() and f['index'] not in used and f['syntax'] == 'modern'), None)
        chosen.append(match)
        if match:
            used.add(match['index'])
    return chosen


def canonical_header(raw, mode):
    if mode == 'simple':
        return raw
    if mode != 'relaxed':
        raise ValueError('unsupported header canonicalization')
    name, value = raw.rstrip(b'\r\n').split(b':', 1)
    value = re.sub(rb'\r\n[ \t]+', b' ', value)
    value = re.sub(rb'[ \t]+', b' ', value).strip(b' \t')
    return name.strip(b' \t').lower() + b':' + value + b'\r\n'


def canonical_body(raw, mode):
    lines = raw.split(b'\r\n')
    if mode == 'relaxed':
        lines = [re.sub(rb'[ \t]+', b' ', line).rstrip(b' \t') for line in lines]
    elif mode != 'simple':
        raise ValueError('unsupported body canonicalization')
    while lines and lines[-1] == b'':
        lines.pop()
    if not lines:
        return b'\r\n' if mode == 'simple' else b''
    return b'\r\n'.join(lines) + b'\r\n'


def tags(signature):
    value = re.sub(rb'\r\n[ \t]+', b' ', signature.split(b':', 1)[1])
    result = {}
    for tag in value.split(b';'):
        name, equal, content = tag.strip().partition(b'=')
        if equal:
            key = name.decode('ascii').lower()
            if key in result:
                raise ValueError('duplicate DKIM tag')
            result[key] = content.strip()
    return result


def hashing_input(raw, signature, names, mode, top_down=False, include_missing=True):
    selected = select(raw, names, top_down=top_down)
    pieces, diagnostics = [], []
    for name, field in zip(names, selected):
        if field is None:
            # RFC 6376 §3.5 includes a null field. dkimpy 1.1.8 select_headers() omits it.
            if not include_missing:
                diagnostics.append({'name': name, 'index': None, 'absent': True, 'omitted': True})
                continue
            piece = canonical_header(name.encode('ascii') + b':\r\n', mode)
            pieces.append(piece)
            diagnostics.append({'name': name, 'index': None, 'absent': True, 'canonical_sha256': hashlib.sha256(piece).hexdigest()})
            continue
        piece = canonical_header(raw[field['start']:field['end']], mode)
        pieces.append(piece)
        diagnostics.append({'name': name, 'index': field['index'], 'start': field['start'], 'end': field['end'], 'canonical_sha256': hashlib.sha256(piece).hexdigest()})
    without_b = re.sub(rb'(?i)(\bb[ \t]*=)[^;]*', rb'\1', signature)
    pieces.append(canonical_header(without_b, mode).rstrip(b'\r\n'))
    return b''.join(pieces), diagnostics


def sign(raw, key, names, mode='relaxed', domain='lab.test', selector='research', include_missing=True):
    info = structure.require_modern(raw)
    if 'from' not in names:
        raise ValueError('From must be signed')
    body = canonical_body(raw[info['boundary'] + 4:], 'relaxed')
    bh = base64.b64encode(hashlib.sha256(body).digest())
    signature = (f'DKIM-Signature: v=1; a=rsa-sha256; c={mode}/relaxed; d={domain};\r\n s={selector}; h={":".join(names)};\r\n bh='.encode() + bh + b'; b=\r\n')
    hashed, selected = hashing_input(raw, signature, names, mode, include_missing=include_missing)
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=hashed, capture_output=True, check=True)
    signature = signature[:-2] + base64.b64encode(result.stdout) + b'\r\n'
    signed = signature + raw
    structure.require_modern(signed)
    return signed, {'signer': 'independent-openssl-reference', 'canonicalization': mode + '/relaxed', 'h': names, 'selected_unsigned': selected, 'hash_input_sha256': hashlib.sha256(hashed).hexdigest()}


def diagnose(raw, public_pem, top_down=False, include_missing=True):
    info = structure.inspect(raw)
    if info['issues'] or any(f['syntax'] != 'modern' for f in info['fields']):
        return {'status': 'parse-error', 'reason': 'outside modern reference domain'}
    signatures = structure.field_bytes(raw, 'dkim-signature')
    if not signatures:
        return {'status': 'none'}
    results = []
    for signature in signatures:
        try:
            params = tags(signature)
            modes = params.get('c', b'simple/simple').decode().split('/')
            body_mode = modes[1] if len(modes) > 1 else 'simple'
            body = canonical_body(raw[info['boundary'] + 4:], body_mode)
            if 'l' in params:
                body = body[:int(params['l'])]
            body_ok = base64.b64encode(hashlib.sha256(body).digest()) == re.sub(rb'\s', b'', params['bh'])
            names = re.sub(rb'\s', b'', params['h']).decode().lower().split(':')
            hashed, selected = hashing_input(raw, signature, names, modes[0], top_down=top_down, include_missing=include_missing)
            with tempfile.TemporaryDirectory() as td:
                sigpath = Path(td) / 'signature.bin'
                sigpath.write_bytes(base64.b64decode(re.sub(rb'\s', b'', params['b']), validate=True))
                result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_pem), '-signature', str(sigpath)], input=hashed, capture_output=True)
            results.append({'status': 'pass' if body_ok and result.returncode == 0 else 'fail', 'body_hash_match': body_ok,
                            'header_signature_match': result.returncode == 0, 'h': names, 'selected': selected,
                            'hash_input_sha256': hashlib.sha256(hashed).hexdigest(), 'openssl_stdout': result.stdout.decode(), 'openssl_stderr': result.stderr.decode()})
        except (ValueError, KeyError, UnicodeError) as exc:
            results.append({'status': 'parse-error', 'reason': str(exc)})
    return {'status': results[0]['status'], 'signatures': results, 'reference_scope': 'modern controlled IMF; crypto only, no duplicate-From policy'}
