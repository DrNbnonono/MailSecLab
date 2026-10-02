from . import structure

VALUES = {'from': (b'Author <author@lab.test>', b'Attacker <attacker@evil.test>'),
          'subject': (b'Original subject', b'Changed subject'),
          'message-id': (b'<original@lab.test>', b'<changed@evil.test>')}


def base(case_id, duplicate=None):
    headers = [b'From: ' + VALUES['from'][0], b'To: recipient@receiver.test',
               b'Date: Thu, 1 Oct 2026 00:00:00 +0000', b'Subject: Original subject',
               b'Message-ID: <original@lab.test>', b'X-Case-ID: ' + case_id.encode()]
    if duplicate:
        index = next(i for i, h in enumerate(headers) if h.lower().startswith(duplicate.encode() + b':'))
        headers.insert(index + 1, duplicate.encode() + b': ' + VALUES[duplicate][1])
    raw = b'\r\n'.join(headers) + b'\r\n\r\nControlled research body.\r\nCase: ' + case_id.encode() + b'\r\n'
    structure.require_modern(raw)
    return raw


def mutate(raw, name, operation):
    if operation == 'unchanged':
        return raw
    info = structure.inspect(raw)
    entries = [raw[f['start']:f['end']] for f in info['fields']]
    locations = [f['index'] for f in info['fields'] if f['name'] == name]
    if not locations:
        raise ValueError('target field missing')
    changed_values = {'from': b'Mutation <mutation@evil.test>', 'subject': b'Mutation subject', 'message-id': b'<mutation@evil.test>'}
    replacement = name.encode() + b': ' + changed_values[name] + b'\r\n'
    if operation == 'insert-before':
        entries.insert(locations[0], name.encode() + b': ' + VALUES[name][1] + b'\r\n')
    elif operation == 'insert-after':
        entries.insert(locations[-1] + 1, name.encode() + b': ' + VALUES[name][1] + b'\r\n')
    elif operation == 'edit-first':
        entries[locations[0]] = replacement
    elif operation == 'edit-last':
        entries[locations[-1]] = replacement
    elif operation == 'reverse' and len(locations) == 2:
        entries[locations[0]], entries[locations[1]] = entries[locations[1]], entries[locations[0]]
    elif operation == 'delete-first':
        del entries[locations[0]]
    elif operation == 'delete-last':
        del entries[locations[-1]]
    else:
        raise ValueError('unknown or inapplicable mutation')
    result = b''.join(entries) + b'\r\n' + raw[info['boundary'] + 4:]
    if structure.field_bytes(raw, 'dkim-signature') != structure.field_bytes(result, 'dkim-signature'):
        raise AssertionError('mutation changed signature bytes')
    return result


def causal_specs():
    for name in VALUES:
        for mode in ('relaxed', 'simple'):
            for count in (1, 2):
                for covered in ((1, 2) if count == 1 else (1, 2, 3)):
                    operations = ('unchanged', 'insert-before', 'insert-after') if count == 1 else ('unchanged', 'edit-first', 'edit-last', 'reverse', 'delete-first', 'delete-last')
                    yield {'field': name, 'mode': mode, 'count': count, 'covered': covered, 'operations': operations}
