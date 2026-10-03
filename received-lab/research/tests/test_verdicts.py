"""verdicts 单测。纯逻辑：AR 解析、差分关系、milter 符号、ENVELOPE 解析；
栈锚：w3 sigprobe2 九格对存档重放文件级四验证器（只读操作，不发送邮件）。"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

import pytest

from research.lib.verdicts import (
    ar_verdicts,
    diff_verdicts,
    envelope_from,
    parse_milter_symbol,
)

SIGPROBE2 = Path("/mnt/e/MailSecLab/received-lab/results/research/w3-20261003a/sigprobe2")

AR_STAMPED = (
    b"Authentication-Results: msl-auth-postfix; dkim=pass (2048-bit key)\r\n"
    b"\theader.d=lab.test header.b=AAAAB;\r\n"
    b"\tdmarc=fail (p=none) header.from=evil.test\r\n"
    b"From: a@lab.test\r\nSubject: x\r\n\r\nbody\r\n"
)


def test_ar_verdicts_parses_stamp_fields():
    v = ar_verdicts(AR_STAMPED)
    assert v["dkim"] == "pass"
    assert v["dmarc"] == "fail"
    assert v["header_d"] == "lab.test"
    assert v["header_from"] == "evil.test"
    assert v["ar_count"] == 1


def test_ar_verdicts_counts_multiple_stamps():
    raw = (b"Authentication-Results: receiver.example; dkim=pass header.d=evil.test\r\n"
           + AR_STAMPED)
    v = ar_verdicts(raw)
    assert v["ar_count"] == 2
    # 聚合取第一条（头区顺序里的第一个 AR）；逐条明细保留在 stamps
    assert v["header_d"] == "evil.test"
    assert len(v["stamps"]) == 2
    assert v["stamps"][1]["dmarc"] == "fail"


def test_ar_verdicts_absent_when_no_stamp():
    v = ar_verdicts(b"From: a@lab.test\r\n\r\nbody\r\n")
    assert v["dkim"] == "absent" and v["dmarc"] == "absent"
    assert v["ar_count"] == 0


def test_diff_verdicts_relations():
    a = {"dkim": {"dkimpy": "fail", "perl": "pass"}, "ar": {"dmarc": "absent"}}
    b = {"dkim": {"dkimpy": "pass", "perl": "pass"}, "ar": {"dmarc": "fail"}}
    d = diff_verdicts(a, b)
    assert d["dkim.dkimpy"]["relation"] == "break"
    assert d["dkim.perl"]["relation"] == "persist"
    assert d["ar.dmarc"]["relation"] == "created"


def test_parse_milter_symbol():
    text = ("2026-10-03 12:00:00 #12345(normal) <6F1>; task; write_log: "
            "id: <x@lab.test>: DMARC_POLICY_REJECT(5.00){evil.test;}")
    assert parse_milter_symbol(text) == "DMARC_POLICY_REJECT"
    assert parse_milter_symbol("R_DKIM_ALLOW(2.00){lab.test;}") == "R_DKIM_ALLOW"
    assert parse_milter_symbol("no symbols here") is None


def test_envelope_from_extracts_first_address():
    resp = ('(ENVELOPE ("Sat, 3 Oct 2026 21:00:00 +0000" "confirm" '
            '(("Bank Security" NIL "security" "lab.test")) '
            '((NIL NIL "bob" "lab.test")) ...)')
    assert envelope_from(resp) == "security@lab.test"


def _container_up(name: str) -> bool:
    try:
        return subprocess.run(
            ["docker", "exec", name, "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
        ).returncode == 0
    except Exception:
        return False


def test_sigprobe2_nine_cell_anchor_replay():
    """锚定：对 w3 sigprobe2 九格存档重放文件级四验证器，逐格复现判决。

    这是 verdicts 层的仪器校验锚（sigprobe2/matrix.json 为已固化结论）。
    只读操作：verify_one 文件扫描 + rspamc 文件扫描，不发送邮件。
    """
    matrix_path = SIGPROBE2 / "matrix.json"
    if not matrix_path.exists():
        pytest.skip("sigprobe2 存档不在本机")
    if not (_container_up("msl-verifiers") and _container_up("msl-rspamd")):
        pytest.skip("验证容器未运行（栈任务择窗后重跑本锚）")

    from research.lib.verdicts import file_verdicts

    rows = json.loads(matrix_path.read_text(encoding="utf-8"))["rows"]
    assert len(rows) == 9, f"预期 9 格，实得 {len(rows)}"
    for row in rows:
        base, path = row["baseline"], row["path"]
        fname = f"{base}.eml" if path == "norelay" else f"{base}-{path}.stored.eml"
        if not (SIGPROBE2 / fname).exists():
            pytest.fail(f"锚文件缺失：{fname}")
        got = file_verdicts(f"/evidence/w3-20261003a/sigprobe2/{fname}")
        for tool, expected in row["verifiers"].items():
            key = "rspamd_file" if tool == "rspamd" else tool
            assert got[key] == expected, (
                f"{base}/{path}/{tool}: 重放 {got[key]} != 锚定 {expected}")
