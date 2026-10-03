"""gramfuzz 单测：口径元组、探针输出解析、corpus phase 小规模端到端、CLI 桩。

stage1/stage2 的容器臂不在单测里跑（需要 docker 研究栈），批量探针的正
确性由 w3 锚定的手工校准（gramfuzz/calibration.json）承担。
"""
import hashlib
import json
import sys

sys.path.insert(0, "/mnt/e/Gramfuzz")

import gramfuzz.funnel as gf
from gramfuzz.grammut import ALL_OPS
from gramfuzz.lab import corpus_check


def test_rfc_load_list_includes_2045():
    # 8601 的 value 规则引用 2045：列表缺它 authres 入口不可派生（105f2bf）。
    assert any(p.endswith("rfc2045.txt") for p in gf.RFCS)


def test_tuple_contract():
    assert gf._tuple(None) == ("error",)
    assert gf._tuple({"error": "boom"}) == ("error",)
    assert gf._tuple({"case": "x", "error": ""}) == ("error",)
    assert gf._tuple({"received_count": 25, "from_in_headers": True,
                      "field_count": 7, "defects": 1}) == (25, True, 7)


def test_parse_probe_output_skips_garbage_and_maps_by_case():
    out = "\n".join([
        "warning: something on stdout",
        '{"case": "a", "received_count": 1, "from_in_headers": true, "field_count": 2}',
        "not json",
        '{"case": "b", "error": "x"}',
        '{"no_case": true}',
        '{"case": "a", "received_count": 9, "from_in_headers": false, "field_count": 1}',
    ])
    rows = gf._parse_probe_output(out)
    assert set(rows) == {"a", "b"}
    assert rows["a"]["received_count"] == 9      # 后行覆盖同行
    assert "error" in rows["b"]


def test_phase_corpus_small_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "RUN_ROOT", tmp_path)
    monkeypatch.setattr(gf, "_entries", lambda: [
        {"name": "from", "symbol": "from", "rfcs": ["rfc5322"]}])
    pt = gf.PriorityTable(None)
    report = gf.phase_corpus("t-run", pt, fresh_per=2, mutated_per=2)
    assert report["files"] == 4

    stage = tmp_path / "t-run" / "gramfuzz"
    corpus = stage / "corpus"
    index = json.loads((stage / "corpus-index.json").read_text(encoding="utf-8"))
    assert len(index) == 4
    assert len(sorted(corpus.glob("*.eml"))) == 4
    fresh = [i for i in index if not i["mutated"]]
    mut = [i for i in index if i["mutated"]]
    assert len(fresh) == 2 and len(mut) == 2
    assert all(i["op"] is None for i in fresh)
    assert all(i["op"] in ALL_OPS for i in mut)
    for item in index:
        raw = (corpus / ("%s.eml" % item["case"])).read_bytes()
        # case_id 先定原则：X-Case-ID 与文件名一致，sha256 与索引一致
        assert ("X-Case-ID: %s\r\n" % item["case"]).encode() in raw
        assert hashlib.sha256(raw).hexdigest() == item["input_sha256"]
    for item in fresh:
        # fresh 样本必须过 corpus_check（F1 纪律）；mutated 不作此断言
        raw = (corpus / ("%s.eml" % item["case"])).read_bytes()
        assert corpus_check(raw) == []


def test_phase_corpus_rerun_wipes_stale_files(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "RUN_ROOT", tmp_path)
    monkeypatch.setattr(gf, "_entries", lambda: [
        {"name": "from", "symbol": "from", "rfcs": ["rfc5322"]}])
    pt = gf.PriorityTable(None)
    gf.phase_corpus("t-run", pt, fresh_per=2, mutated_per=2)
    corpus = tmp_path / "t-run" / "gramfuzz" / "corpus"
    stale = corpus / "gf-from-fresh-9999.eml"
    stale.write_bytes(b"stale\r\n\r\nx\r\n")
    gf.phase_corpus("t-run", pt, fresh_per=1, mutated_per=1)
    assert not stale.exists()                    # corpus phase 是目录唯一权威
    assert len(sorted(corpus.glob("*.eml"))) == 2


def test_cli_stage2_report_stubs_exit_2(capsys):
    assert gf.main(["t-run", "--phase", "stage2"]) == 2
    assert "任务 6" in capsys.readouterr().out
    assert gf.main(["t-run", "--phase", "report"]) == 2
    assert "任务 7" in capsys.readouterr().out
