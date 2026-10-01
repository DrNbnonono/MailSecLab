import json
from pathlib import Path
import subprocess
import sys

import pytest


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "mailtrace.cli", *map(str, args)], capture_output=True, encoding="utf-8", check=False)


def test_json_cli_stdout_is_one_report():
    fixture = Path(__file__).resolve().parents[1] / "docs/contracts/basic-example.eml"
    result = run_cli("analyze", fixture, "--json")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert data["message"]["subject"] == "项目进度"
    assert data["route"][1]["delay_seconds"] == 17


def test_text_cli_displays_claims():
    fixture = Path(__file__).resolve().parents[1] / "docs/contracts/basic-example.eml"
    result = run_cli("analyze", fixture)
    assert result.returncode == 0
    assert "MailTrace" in result.stdout
    assert "未主动验证" in result.stdout
    assert "PRIVATE_IP_EXPOSED" in result.stdout


@pytest.mark.parametrize("kind", ["missing", "empty", "oversize"])
def test_file_errors_have_no_stdout(tmp_path, kind):
    path = tmp_path / "mail.eml"
    if kind == "empty":
        path.write_bytes(b"")
    elif kind == "oversize":
        path.write_bytes(b"x" * (10 * 1024 * 1024 + 1))
    result = run_cli("analyze", path, "--json")
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr


def test_exact_size_limit_is_accepted(tmp_path):
    path = tmp_path / "mail.eml"
    prefix = b"Subject: limit\n\n"
    path.write_bytes(prefix + b"x" * (10 * 1024 * 1024 - len(prefix)))
    result = run_cli("analyze", path, "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["source"]["input_size_bytes"] == 10 * 1024 * 1024


@pytest.mark.parametrize("limit", ["0", "-1", "1.5"])
def test_invalid_limit_is_parameter_error(tmp_path, limit):
    result = run_cli("analyze", tmp_path / "mail.eml", "--chain-limit", limit)
    assert result.returncode == 2


def test_terminal_controls_are_escaped(tmp_path):
    path = tmp_path / "control.eml"
    path.write_bytes(b"Subject: \x1b[2Jdemo\x07\n")
    result = run_cli("analyze", path)
    assert result.returncode == 0
    assert "\x1b" not in result.stdout
    assert "\x07" not in result.stdout
    data = json.loads(run_cli("analyze", path, "--json").stdout)
    assert "\x1b" in data["headers"][0]["raw"]
