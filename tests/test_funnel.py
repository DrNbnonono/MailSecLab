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


def test_cli_report_runs_phase_report(tmp_path, monkeypatch):
    # report 已在任务 7 实现：真跑 phase_report（真数据需 docker 栈，
    # 单测覆盖见 test_phase_report_*）；无 stage2.json 时报缺不静默。
    monkeypatch.setattr(gf, "RUN_ROOT", tmp_path)
    try:
        gf.main(["t-run", "--phase", "report"])
    except RuntimeError as exc:
        assert "stage2.json" in str(exc)
    else:
        raise AssertionError("缺 stage2.json 必须报错")


def test_imap_tokens_handles_literals_quotes_and_escapes():
    # imaplib 把响应拆成 (文本段, 字面量段) 交替；{n} 标记后整段是一个 token。
    # 真实结构：FETCH (ENVELOPE (date subject from-group sender ...))。
    parts = [b'1 (ENVELOPE ("date" {32}',
             b'literal subj (parens) and spaces',
             b' (("Bank \\\\Security" NIL "security" "bank.test")) NIL NIL NIL NIL NIL NIL NIL))']
    toks = gf._imap_tokens(parts)
    assert toks[0] == b"1"
    assert b'literal subj (parens) and spaces' in toks      # 字面量保完整
    fields = gf._find_envelope(gf._nested(toks))
    assert fields is not None and fields[0] == b"date"      # 字段表直取
    slot = gf._envelope_from_slot(parts)
    assert slot["from_slot"] == "security@bank.test"
    assert slot["from_group"] == ["security@bank.test"]


def test_imap_tokens_nil_from_group():
    parts = [b'1 (ENVELOPE ("date" "s" NIL NIL NIL NIL NIL NIL NIL NIL))']
    slot = gf._envelope_from_slot(parts)
    assert slot["from_slot"] is None
    assert slot["from_group"] is None


def test_first_from_value_and_addr_extraction():
    raw = (b"X-Junk: 1\r\nFrom : Bank Security <security@bank.test>\r\n"
           b" extra\r\nFrom: second@lab.test\r\n\r\nbody\r\n")
    val = gf._first_from_value(raw)
    assert val.startswith("From : Bank Security") and "extra" in val  # obs + 折行
    assert gf._addr_from_value(val) == "security@bank.test"          # 第一实例
    assert gf._addr_from_value("From: plain@x.test") == "plain@x.test"
    assert gf._addr_from_value(None) is None


def test_fold_wsp_and_display_approx():
    # 任务 6 遗留的归一化不对称：ENVELOPE 字面量保留原始 tab，头区抽取折叠
    # 空白，Dovecot 组地址时又丢 token 间空白——统一折到零空白再比。
    assert gf._fold_wsp("a@b\tc  d\r\n e") == "a@bcde"
    assert gf._fold_wsp(None) is None
    assert gf._fold_wsp("") == ""
    assert gf._display_approx("y&@[\t\tsw  ]", "y&@[ sw ]") is True   # 仅空白
    assert gf._display_approx("a@%.~", "a@ %.~") is True              # 折叠丢空格
    assert gf._display_approx("attacker@x.test", "bank@y.test") is False
    assert gf._display_approx(None, "a@b") is False
    assert gf._display_approx("a@b", "a@b") is False                  # 无差异


def test_classify_d_excludes_whitespace_only():
    views = {"python": (0, True, 5), "go": (0, True, 5), "node": (0, True, 5)}
    approx = dict(views=views, envelope_from="y&@[\tsw ]",
                  header_from_first="y&@[ sw ]", display_approx=True)
    assert gf.classify(approx) == ["U"]                      # 仅空白差异不算 D
    real = dict(views=views, envelope_from="attacker@x.test",
                header_from_first="bank@y.test")
    assert gf.classify(real) == ["D"]
    none_hdr = dict(views=views, envelope_from="missing_mailbox@missing_domain",
                    header_from_first=None)
    assert gf.classify(none_hdr) == ["D"]                    # 头区抽不到 From 仍算 D


def test_dedup_and_cap_survivors_over_cap_mixed_views():
    # 全量首跑回归（2026-10-03）：10119 幸存者 > cap 才首次走进去重路径，
    # ("error",) 与 (0, True, 5) 经 JSON 往返后是混型 list，直接 sorted 抛
    # TypeError。规范化键修复后：同视图集合去重、按入口等额抽样。
    views_a = {"python": ["error"], "go": [0, True, 5], "node": [25, True, 5]}
    views_b = {"python": [0, True, 5], "go": [0, True, 5], "node": [0, True, 5]}
    rows = {}
    survivors = []
    for i in range(30):
        case = "c%03d" % i
        entry = ("from", "received")[i % 2]
        if i % 4 == 0:      # 8 例同视图形态 b：验证语义去重
            views = views_b
        else:               # 22 例各自带独特 received_count：验证不去重
            views = dict(views_a, node=[i, True, 5])
        rows[case] = {"entry": entry, "views": views}
        survivors.append(case)
    capped = gf._dedup_and_cap(rows, survivors, 10)
    assert len(capped) == 10
    assert len(set(capped)) == 10                       # 无重复
    assert all(c in rows for c in capped)
    # 语义去重：同 (entry, 视图集合) 只留首个——8 例 views_b 全是 from 入口
    # 只留 1 例，22 例独特视图全保留（from 7 + received 15）→ uniq 共 23
    uniq = []
    seen = set()
    for case in survivors:
        key = (rows[case]["entry"], tuple(sorted(json.dumps(v)
                                                 for v in rows[case]["views"].values())))
        if key not in seen:
            seen.add(key)
            uniq.append(case)
    assert len(uniq) == 23
    assert set(capped) <= set(uniq)
    # 分层：两入口轮流，capped 前两个应分属不同入口
    assert rows[capped[0]]["entry"] != rows[capped[1]]["entry"]


def test_dedup_and_cap_under_cap_returns_all():
    rows = {"c1": {"entry": "from", "views": {"python": ["error"],
                                              "go": [0, True, 5]}},
            "c2": {"entry": "from", "views": {"python": [0, False, 3],
                                              "go": [0, True, 5]}}}
    assert gf._dedup_and_cap(rows, ["c1", "c2"], 400) == ["c1", "c2"]


def _mk_stage(tmp_path):
    stage = tmp_path / "t-run" / "gramfuzz"
    for d in ("corpus", "relay/postfix", "relay/exim", "relay/osmtpd",
              "sign", "imap"):
        (stage / d).mkdir(parents=True)
    return stage


def test_phase_report_gates_and_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "RUN_ROOT", tmp_path)
    stage = _mk_stage(tmp_path)
    raw = b"From: a@lab.test\r\nSubject: c\r\n\r\nx\r\n"
    sha = hashlib.sha256(raw).hexdigest()
    for case in ("c1", "c2", "c3"):
        (stage / "corpus" / ("%s.eml" % case)).write_bytes(raw)
    for t in ("postfix", "exim"):
        (stage / "relay" / t / "c1.smtp.txt").write_bytes(b"220 t\r\n")
        (stage / "relay" / t / "c1.stored.raw").write_bytes(b"stored")
    (stage / "relay" / "osmtpd" / "c1.smtp.txt").write_bytes(b"220 t\r\n")
    rows = [
        # T：证据四件套齐 → lab_confirmed
        {"case": "c1", "entry": "from", "op": "guided.fold-line",
         "input_sha256": sha,
         "views": {"python": (0, True, 5), "go": (0, True, 5), "node": (1, True, 5)},
         "relay": {"postfix": {"captured": True, "gen_preserved": False,
                               "smtp_code": "250"},
                   "exim": {"captured": True, "gen_preserved": True,
                            "smtp_code": "250"},
                   "osmtpd": {"captured": False, "smtp_code": "550"}},
         "series": ["P", "T"]},
        # 纯 P：留在 stage1.json，不进 candidates
        {"case": "c2", "entry": "from", "op": None, "input_sha256": sha,
         "views": {"python": (0, True, 5), "go": (0, True, 5), "node": (1, True, 5)},
         "relay": {}, "series": ["P"]},
        # T 但 sha 对不上 + 无转录 → 证据缺件，lab_confirmed=false
        {"case": "c3", "entry": "from", "op": "byte.flip",
         "input_sha256": "0" * 64,
         "views": {"python": (0, True, 5), "go": (0, True, 5), "node": (0, True, 5)},
         "relay": {"postfix": {"captured": True, "gen_preserved": True},
                   "exim": {"captured": True, "gen_preserved": True}},
         "series": ["T"]},
    ]
    (stage / "stage2.json").write_text(json.dumps(rows), encoding="utf-8")
    out = gf.phase_report("t-run")
    assert out["candidates_total"] == 2
    assert out["lab_confirmed_total"] == 1
    assert out["counts"] == {"P": 2, "T": 2, "X": 0, "D": 0, "U": 0}
    by_case = {c["case"]: c for c in out["candidates"]}
    assert "c2" not in by_case                        # 纯 P 排除
    c1 = by_case["c1"]
    assert c1["lab_confirmed"] is True and c1["missing_evidence"] == []
    assert c1["evidence"]["input"] == "corpus/c1.eml"
    assert c1["evidence"]["relay"]["postfix"]["stored_raw"] == \
        "relay/postfix/c1.stored.raw"
    assert "stored_raw" not in c1["evidence"]["relay"]["osmtpd"]  # 未捕获
    assert c1["root_cause"] is None and c1["review_flag"] is None
    assert c1["summary"].startswith("from（op=guided.fold-line）")
    c3 = by_case["c3"]
    assert c3["lab_confirmed"] is False
    assert "input-sha256-mismatch" in c3["missing_evidence"]
    assert "relay-postfix-transcript" in c3["missing_evidence"]
    disk = json.loads((stage / "candidates.json").read_text(encoding="utf-8"))
    assert disk["gate_for"] and disk["generated_at"] and disk["run_id"] == "t-run"
    assert len(disk["candidates"]) == 2


def test_phase_report_x_and_d_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "RUN_ROOT", tmp_path)
    stage = _mk_stage(tmp_path)
    raw = b"From: a@lab.test\r\nSubject: c\r\n\r\nx\r\n"
    sha = hashlib.sha256(raw).hexdigest()
    (stage / "corpus" / "x1.eml").write_bytes(raw)
    (stage / "corpus" / "d1.eml").write_bytes(raw)
    for fname in ("x1-sign.eml", "x1-sign.smtp.txt", "x1-sign.stored.raw"):
        (stage / "sign" / fname).write_bytes(b"x")
    for fname in ("d1.smtp.txt", "d1.stored.raw", "d1.envelope.json"):
        (stage / "imap" / fname).write_bytes(b"x")
    rows = [
        {"case": "x1", "entry": "dkim-tags", "op": "guided.space-colon",
         "input_sha256": sha,
         "views": {"python": (0, True, 5), "go": (0, True, 5), "node": (0, True, 5)},
         "relay": {}, "series": ["X"],
         "sign": {"sign_case": "x1-sign",
                  "file": {"dkimpy": "parse-error", "perl": "pass",
                           "go": "pass", "rspamd": "pass"},
                  "postfix": {"captured": True,
                              "verdicts": {"dkimpy": "pass", "perl": "pass",
                                           "go": "pass", "rspamd": "pass"}}}},
        {"case": "d1", "entry": "from", "op": "guided.dup-line",
         "input_sha256": sha,
         "views": {"python": (0, True, 5), "go": (0, True, 5), "node": (0, True, 5)},
         "relay": {}, "series": ["D"],
         "imap": {"uid": "42", "locator": "header"},
         "envelope_from": "attacker@x.test", "header_from_first": "bank@y.test"},
    ]
    (stage / "stage2.json").write_text(json.dumps(rows), encoding="utf-8")
    out = gf.phase_report("t-run")
    assert out["counts"] == {"P": 0, "T": 0, "X": 1, "D": 1, "U": 0}
    by_case = {c["case"]: c for c in out["candidates"]}
    x1 = by_case["x1"]
    assert x1["lab_confirmed"] is True
    assert x1["evidence"]["sign"]["stored_raw"] == "sign/x1-sign.stored.raw"
    assert x1["evidence"]["verdicts"]["dkimpy@postfix"] == "pass"
    assert "parse-error" in x1["summary"] or "dkimpy" in x1["summary"]
    assert by_case["d1"]["lab_confirmed"] is True
    assert by_case["d1"]["evidence"]["imap"]["envelope"] == "imap/d1.envelope.json"
    # X 行缺签名存档 → 缺件不确认
    (stage / "sign" / "x1-sign.stored.raw").unlink()
    out2 = gf.phase_report("t-run")
    x1b = {c["case"]: c for c in out2["candidates"]}["x1"]
    assert x1b["lab_confirmed"] is False
    assert "sign-stored_raw" in x1b["missing_evidence"]
