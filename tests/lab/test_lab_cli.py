import json
import subprocess
import sys


def command(*arguments):
    return subprocess.run([sys.executable, "-m", "mailtrace_lab.cli", *map(str, arguments)], capture_output=True, encoding="utf-8")


def test_cli_forge_and_reproduce(tmp_path):
    spec = tmp_path / "case.json"
    spec.write_text('{"received_count":51}', encoding="utf-8")
    root = tmp_path / "archive"
    first = command("--store", root, "forge", spec)
    assert first.returncode == 0, first.stderr
    manifest = json.loads(first.stdout)
    assert manifest["snapshots"][0]["metrics"]["recognized_received_count"] == 51
    second = command("--store", root, "reproduce", manifest["id"])
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)["derived_from"] == manifest["id"]


def test_cli_binary_diff_and_errors(tmp_path):
    first, second = tmp_path / "first.eml", tmp_path / "second.eml"
    first.write_bytes(b"X-Binary: \xff\r\n\r\n")
    second.write_bytes(b"X-Binary: \xfe\r\n\r\n")
    result = command("--store", tmp_path / "archive", "diff", first, second)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["diffs"][0]["summary"]["value_changed"] == 1
    missing = command("diff", tmp_path / "missing.eml", second)
    assert missing.returncode == 1
    assert missing.stdout == ""
