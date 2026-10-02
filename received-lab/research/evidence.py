import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'results' / 'research'


def validate_id(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', value) or '..' in value:
        raise ValueError('invalid evidence identifier')
    return value


def write_once(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
    return hashlib.sha256(data).hexdigest()


def json_once(path, value):
    return write_once(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode())


def event(path, value):
    with Path(path).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), **value}, ensure_ascii=False) + '\n')


def command(argv, directory, label, timeout=120, input_bytes=None):
    directory = Path(directory)
    try:
        result = subprocess.run(argv, input=input_bytes, capture_output=True, timeout=timeout, cwd=ROOT)
        state, code, stdout, stderr = 'ok' if result.returncode == 0 else 'tool-error', result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        state, code, stdout, stderr = 'timeout', None, exc.stdout or b'', exc.stderr or b''
    except OSError as exc:
        state, code, stdout, stderr = 'tool-error', None, b'', str(exc).encode()
    write_once(directory / (label + '.stdout'), stdout)
    write_once(directory / (label + '.stderr'), stderr)
    data = {'argv': argv, 'status': state, 'exit_code': code, 'input_sha256': hashlib.sha256(input_bytes).hexdigest() if input_bytes is not None else None}
    json_once(directory / (label + '.process.json'), data)
    return {**data, 'stdout': stdout.decode('utf-8', 'replace'), 'stderr': stderr.decode('utf-8', 'replace')}


def new_run(run_id, stage):
    RESULTS.mkdir(parents=True, exist_ok=True)
    used = sum(p.stat().st_size for p in RESULTS.rglob('*') if p.is_file())
    if used >= 20 * 1024**3:
        raise RuntimeError('20 GiB artifact budget reached')
    path = RESULTS / validate_id(run_id)
    path.mkdir(exist_ok=False)
    json_once(path / 'request.json', {'stage': stage, 'run_id': run_id, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'artifact_bytes_before': used})
    return path
