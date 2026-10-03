"""最小重现子：对生成头块做字节级 ddmin，谓词由家族签名决定。

谓词接缝（A2 执行要点，对计划 A2.3 的落地修正——每步过中继不可行）：
- P 族（纯 P 与 P+T 的基础层）：三 parser 元组差分重放（批量探针，单文件
  模式），判定「三家元组不一致」且差分特征与族签名一致（cluster._pdiff）。
- X 族（P+X、P+T+X 链）：四验证器文件级判定形态重放（verify_one 同一
  仪器口径），判定形态与族签名一致。keep 行必须含 DKIM-Signature——签名
  结构（s2 注入：生成头插在已签 DKIM-Signature 之上）不能被砍。
- T 族专属验证：P 谓词缩到位后，一次性把最小子过三台中继（SURGERY.md
  捕获路由手术，跑完立即回滚）验证 gen 存活形态与族签名一致——批量收尾，
  不是每步。
- D 族（ENVELOPE 对照）同样批量收尾。

ddmin 只砍头区生成块，模板/定位行（Subject/X-Case-ID/Message-ID/To/Date/
DKIM-Signature/精确模板 From）不参与——定位与签名所需。行内字节缩减不许
把头区行清空（那会制造空行=头区提前结束的语料伪影，F1 教训）。

执行模型：多族 wave 批处理——每一步同时推进全部活跃族的当前试验集，
三个 parser 探针 / 四个验证器对整批文件各跑一次（docker exec 摊销），
单族毫秒-秒级谓词成本由此成立。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

# ---- 纯 ddmin 核心（单族参考实现，单测覆盖） ----

FROM_TMPL = b"From: Bank Security <security@lab.test>"
TO_TMPL = b"To: bob@lab.test"
DATE_TMPL = b"Date: Sat, 3 Oct 2026 23:30:00 +0000"
_LOCATOR_RE = re.compile(rb"^(Subject|X-Case-ID|Message-ID)[\t ]*:", re.IGNORECASE)


def _is_keep(line: bytes) -> bool:
    """模板/定位行判定：定位行按前缀（突变后仍可辨认），To/Date/From 按精确
    模板值（被突变过的实例可缩——那正是机制字节）。"""
    return (line == FROM_TMPL or line == TO_TMPL or line == DATE_TMPL
            or _LOCATOR_RE.match(line) is not None)


def split_candidate(raw: bytes) -> tuple[list[bytes], list[bool]]:
    """整信拆行；返回 (lines, removable)。头区（首个空行之前）中非 keep 的
    行可缩；空行分隔符与正文冻结（P 谓词不看正文，冻结保住 corpus_check
    的可发送结构）。bare LF 语料不在缩减域（w4 corpus_check 已拦截）。"""
    lines = raw.split(b"\r\n")
    removable = []
    in_zone = True
    for line in lines:
        if in_zone:
            if line == b"":
                in_zone = False
                removable.append(False)   # 分隔符
            else:
                removable.append(not _is_keep(line))
        else:
            removable.append(False)       # 正文
    return lines, removable


def x_frozen_split(raw: bytes) -> tuple[bytes, bytes]:
    """签名臂（s2 注入结构）拆分：生成块（可缩）与已签冻结块。

    冻结块 = 最后一条 DKIM-Signature 起到结尾（其折叠行 + 模板 + 正文）。
    生成块里自带的 DKIM-Signature 行（dkim-tags 入口）不会被误判——只认
    紧邻模板 From 之前的那条（reference.sign 的输出布局）。
    """
    lines = raw.split(b"\r\n")
    idx_from = lines.index(FROM_TMPL)
    j = max(i for i in range(idx_from) if lines[i].startswith(b"DKIM-Signature"))
    gen = b"\r\n".join(lines[:j]) + b"\r\n" if j > 0 else b""
    frozen = b"\r\n".join(lines[j:])
    return gen, frozen


def _chunks(seq: list, k: int) -> list[list]:
    """把 seq 切成 k 个连续块（ddmin 标准几何）。"""
    if k <= 1:
        return [list(seq)] if seq else []
    size = max(1, len(seq) // k)
    out = [seq[i:i + size] for i in range(0, len(seq), size)]
    return out if out else [[]]


def ddmin_header(raw: bytes, pred, max_steps: int = 4000) -> bytes:
    """单族参考实现：行级半分 → 每个可缩行的行内字节级半分。"""
    lines, removable = split_candidate(raw)
    steps = [0]

    def check(cand_lines) -> bool:
        steps[0] += 1
        if steps[0] > max_steps:
            raise RuntimeError("ddmin step cap exceeded")
        return pred(b"\r\n".join(cand_lines))

    # 行级
    r_idx = [i for i, r in enumerate(removable) if r]
    k = 2
    while len(r_idx) > 0:
        chunks = _chunks(r_idx, k)
        applied = False
        for ch in chunks:
            drop = set(ch)
            trial = [l for i, l in enumerate(lines) if i not in drop]
            if check(trial):
                lines = trial
                removable = [r for i, r in enumerate(removable) if i not in drop]
                r_idx = [i for i, r in enumerate(removable) if r]
                k = 2
                applied = True
                break
        if applied:
            continue
        if k < len(r_idx):
            k *= 2
        else:
            break
    # 行内字节级（逐可缩行；不许清空行）
    for i in range(len(lines)):
        if not removable[i]:
            continue
        k = 2
        while len(lines[i]) > 1:
            span = list(range(len(lines[i])))
            chunks = _chunks(span, k)
            applied = False
            for ch in chunks:
                drop = set(ch)
                trial_line = bytes(b for p, b in enumerate(lines[i]) if p not in drop)
                if trial_line and check(lines[:i] + [trial_line] + lines[i + 1:]):
                    lines[i] = trial_line
                    k = 2
                    applied = True
                    break
            if applied:
                continue
            if k < len(lines[i]):
                k *= 2
            else:
                break
    return b"\r\n".join(lines)


# ---- wave 引擎（多族批处理；谓词摊销到每波一次探针/验证器批跑） ----

class FamState:
    """一个族的 ddmin 状态机（行级→字节级），由 wave 驱动器推进。"""

    def __init__(self, fam_id: str, raw: bytes, pred, track: str,
                 seed_gen: bytes | None = None):
        self.fam_id = fam_id
        self.pred = pred
        self.track = track
        if track == "x":
            gen, frozen = x_frozen_split(raw)
            self.frozen = frozen
            if seed_gen is not None:
                gen = seed_gen   # P-min 种子（谓词已验过则用，见 phase_x）
            glines = gen.split(b"\r\n")
            if glines and glines[-1] == b"":
                glines = glines[:-1]
            self.lines = glines
            self.removable = [True] * len(self.lines)
        else:
            self.lines, self.removable = split_candidate(raw)
            self.frozen = None
        self.phase = "line"
        self.k = 2
        self.bidx = None
        self.done = len(self.lines) == 0
        self.failed = None
        self.steps = 0
        self.trials = None   # 本波试验：[(tid, lines)]

    # -- 试验生成（试验 = (tid, kind, meta, payload)，见 advance） --
    def next_trials(self, cap: int = 8) -> list[tuple]:
        if self.done:
            return []
        self.trials = []
        if self.phase == "line":
            r_idx = [i for i, r in enumerate(self.removable) if r]
            if not r_idx:
                self._enter_byte_phase()
            else:
                for ch in _chunks(r_idx, self.k)[:cap]:
                    drop = frozenset(ch)
                    self.trials.append((len(self.trials), "line", drop,
                                        [l for i, l in enumerate(self.lines)
                                         if i not in drop]))
                if self.trials:
                    return self.trials
        if self.phase == "byte":
            while self.bidx is not None and not self.trials:
                line = self.lines[self.bidx]
                if len(line) <= 1:
                    self._next_byte_line()
                    continue
                for ch in _chunks(list(range(len(line))), self.k)[:cap]:
                    drop = set(ch)
                    trial_line = bytes(b for p, b in enumerate(line) if p not in drop)
                    if trial_line:
                        self.trials.append((len(self.trials), "byte", self.bidx,
                                            trial_line))
                if self.trials:
                    return self.trials
                self._advance_byte_granularity()
        return self.trials or []

    def _enter_byte_phase(self):
        self.phase = "byte"
        self._next_byte_line()

    def _next_byte_line(self):
        nxt = [i for i, r in enumerate(self.removable)
               if r and (self.bidx is None or i > self.bidx)]
        self.bidx = nxt[0] if nxt else None
        self.k = 2
        if self.bidx is None:
            self.done = True

    def _advance_byte_granularity(self):
        line = self.lines[self.bidx] if self.bidx is not None else b""
        if self.k < len(line):
            self.k *= 2
        else:
            self._next_byte_line()

    # -- 结果推进 --
    def advance(self, results: dict[int, bool]):
        """results: trial_id → 谓词结果。应用首个成功试验；否则升粒度。"""
        if self.done or not self.trials:
            return
        self.steps += len(self.trials)
        for tid, kind, meta, payload in self.trials:
            if results.get(tid):
                if kind == "line":
                    self.removable = [r for i, r in enumerate(self.removable)
                                      if i not in meta]
                    self.lines = payload
                else:
                    self.lines[meta] = payload
                self.k = 2
                self.trials = None
                return
        # 全部失败：升粒度
        if self.phase == "line":
            r_idx = [i for i, r in enumerate(self.removable) if r]
            if self.k < len(r_idx):
                self.k *= 2
            else:
                self._enter_byte_phase()
        else:
            self._advance_byte_granularity()
        self.trials = None

    def candidate(self) -> bytes:
        if self.track == "x":
            if not self.lines:
                return self.frozen
            return b"\r\n".join(self.lines) + b"\r\n" + self.frozen
        return b"\r\n".join(self.lines)

    def trial_bytes(self, kind: str, meta, payload) -> bytes:
        """试验 (kind, meta, payload) → 完整候选字节（与 candidate 同构）。"""
        if kind == "line":
            lines = payload
        else:
            lines = self.lines[:meta] + [payload] + self.lines[meta + 1:]
        if self.track == "x":
            if not lines:
                return self.frozen
            return b"\r\n".join(lines) + b"\r\n" + self.frozen
        return b"\r\n".join(lines)

    def min_gen_block(self) -> bytes:
        """幸存的可缩行（含结尾 CRLF）——T 验证的 gen 存活判据。"""
        return b"".join(l + b"\r\n" for l, r in zip(self.lines, self.removable) if r)


# ---- 实验室接线（docker 批跑；懒导入，单测不触发） ----

RUN_W4 = "w4-20261003a"
RUN_W5 = "w5-20261003a"
KB2_EXPECT = {"dkimpy": "parse-error", "perl": "pass", "go": "pass", "rspamd": "pass"}
PARSER_CONTAINERS = {"python": "msl-client", "go": "msl-verifiers",
                     "node": "parser-node"}

# 三验证器批跑：一次 docker exec；dkimpy 进程内（import 同一份 verify_one），
# perl/go 在容器内逐文件 subprocess（与 verify_one.main 的命令完全一致，
# classify 也用同一份代码——零仪器漂移，省掉逐文件 python 启动）。
_VERIFY_BATCH = """
import json, subprocess, sys
sys.path.insert(0, "/opt/research/lib")
import verify_one

for path in sys.argv[1:]:
    raw = open(path, "rb").read()
    out, err = verify_one.run_dkimpy(raw)
    print(json.dumps({"file": path, "tool": "dkimpy", "status":
                      verify_one.classify_text("dkimpy", out + "\\n" + err, 0)}))
    for tool, cmd in (("perl", ["perl", "/usr/local/bin/verify_perl.pl"]),
                      ("go", ["dkim-verify"])):
        proc = subprocess.run(cmd, input=raw, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30, check=False)
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        print(json.dumps({"file": path, "tool": tool, "status":
                          verify_one.classify_text(tool, out + "\\n" + err,
                                                   proc.returncode)}))
"""


def sh(args, timeout=900, stdin=None):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, input=stdin)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def deliver_probes() -> None:
    """三份批量探针 cp 进容器（同 funnel._deliver_probes 的交付路径）+ go 预编译。"""
    from gramfuzz.lab import PARSERS_DIR
    pairs = [("msl-client", PARSERS_DIR / "parse_batch.py", "/tmp/gf-pb.py"),
             ("msl-verifiers", PARSERS_DIR / "parse_batch.go", "/tmp/gf-pb.go"),
             ("parser-node", PARSERS_DIR / "parse_batch.js", "/tmp/gf-pb.js")]
    for ctr, src, dst in pairs:
        rc, _, err = sh(["docker", "cp", str(src), "%s:%s" % (ctr, dst)], timeout=120)
        if rc != 0:
            raise RuntimeError("docker cp %s -> %s 失败：%s" % (src, ctr, err.strip()))
    rc, _, err = sh(["docker", "exec", "msl-verifiers", "go", "build",
                     "-o", "/tmp/gf-pb-go", "/tmp/gf-pb.go"], timeout=300)
    if rc != 0:
        raise RuntimeError("go build 探针失败：%s" % err.strip()[-400:])


def _probe_rows(out: str) -> dict[str, dict]:
    rows = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "case" in rec:
            rows[rec["case"]] = rec
    return rows


def _view_tuple(rec: dict | None):
    """探针行 → stage-1 比较元组（funnel._tuple 同口径）。探针缺行 = None。"""
    if rec is None or "error" in rec:
        return ("error",) if rec is not None else None
    return (rec["received_count"], rec["from_in_headers"], rec["field_count"])


def parser_probe_dir(host_dir: Path, ev_dir: str) -> dict[str, dict]:
    """一个目录过三 parser → {stem: {python: tuple|None, go:…, node:…}}。"""
    nfiles = len(list(host_dir.glob("*.eml")))
    if not nfiles:
        return {}
    rc, out, err = sh(["docker", "exec", PARSER_CONTAINERS["python"],
                       "python3", "/tmp/gf-pb.py", ev_dir], timeout=1800)
    if rc != 0 and not out.strip():
        raise RuntimeError("python 探针失败：%s" % err.strip()[-400:])
    py = _probe_rows(out)
    # glob 对不存在目录静默返回空且 rc=0——w5 首跑的真实事故，必须显式拦下
    if len(py) < nfiles:
        raise RuntimeError("python 探针只回 %d/%d 行（ev_dir=%s 是否存在？）：%s"
                           % (len(py), nfiles, ev_dir, err.strip()[-200:]))
    rc, out, err = sh(["docker", "exec", PARSER_CONTAINERS["go"],
                       "/tmp/gf-pb-go", ev_dir], timeout=1800)
    if rc != 0 and not out.strip():
        raise RuntimeError("go 探针失败：%s" % err.strip()[-400:])
    go = _probe_rows(out)
    if len(go) < nfiles:
        raise RuntimeError("go 探针只回 %d/%d 行（ev_dir=%s 是否存在？）：%s"
                           % (len(go), nfiles, ev_dir, err.strip()[-200:]))
    # parser-node 无 /evidence 挂载：整目录 tar 进 /tmp（绝不逐文件 exec）。
    import io
    import tarfile as _tar
    buf = io.BytesIO()
    with _tar.open(fileobj=buf, mode="w:gz") as tf:
        for f in sorted(host_dir.glob("*.eml")):
            tf.add(f, arcname="%s/%s" % (host_dir.name, f.name))
    sh(["docker", "exec", PARSER_CONTAINERS["node"], "rm", "-rf",
        "/tmp/" + host_dir.name], timeout=120)
    proc = subprocess.run(["docker", "exec", "-i", PARSER_CONTAINERS["node"],
                           "tar", "xzf", "-", "-C", "/tmp"],
                          input=buf.getvalue(), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=600, check=True)
    rc, out, err = sh(["docker", "exec", "-e", "NODE_PATH=/app/node_modules",
                       PARSER_CONTAINERS["node"], "node", "/tmp/gf-pb.js",
                       "/tmp/" + host_dir.name], timeout=1800)
    if rc != 0 and not out.strip():
        raise RuntimeError("node 探针失败：%s" % err.strip()[-400:])
    node = _probe_rows(out)
    if len(node) < nfiles:
        raise RuntimeError("node 探针只回 %d/%d 行：%s"
                           % (len(node), nfiles, err.strip()[-200:]))
    stems = {f.stem for f in host_dir.glob("*.eml")}
    return {s: {"python": _view_tuple(py.get(s)),
                "go": _view_tuple(go.get(s)),
                "node": _view_tuple(node.get(s))} for s in stems}


def _rspamd_status(payload: dict) -> str:
    symbols = payload.get("symbols") or {}
    if "R_DKIM_ALLOW" in symbols:
        return "pass"
    if "R_DKIM_REJECT" in symbols:
        return "fail"
    if "R_DKIM_TEMPFAIL" in symbols:
        return "temp-error"
    if "R_DKIM_PERMFAIL" in symbols:
        return "fail"
    if "R_DKIM_NA" in symbols:
        return "none"
    action = str(payload.get("action") or "").lower()
    if action == "reject":
        return "policy-reject"
    return "none"


def verifier_batch(ev_files: list[str]) -> dict[str, dict]:
    """一批文件过四验证器 → {ev_path: {dkimpy/perl/go/rspamd: status}}。"""
    out: dict[str, dict] = {f: {} for f in ev_files}
    if not ev_files:
        return out
    proc = subprocess.run(["docker", "exec", "-i", "msl-verifiers",
                           "python3", "-", *ev_files],
                          input=_VERIFY_BATCH.encode(), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=1800, check=False)
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
            out.setdefault(rec["file"], {})[rec["tool"]] = rec["status"]
        except (json.JSONDecodeError, KeyError):
            pass
    # rspamd：rspamc --json --compact 多文件（每行一个 JSON，带 filename）
    rc, stdout, err = sh(["docker", "exec", "msl-rspamd", "rspamc",
                          "--json", "--compact", *ev_files], timeout=1800)
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        fname = payload.get("filename")
        if fname:
            out.setdefault(fname, {})["rspamd"] = _rspamd_status(payload)
    return out


# ---- 谓词工厂（族签名 → 可重放谓词；定义进 reduce-report 供审计） ----

def p_predicate(fam_feats: tuple):
    """P 谓词：三 parser 元组差分重放，差分特征与族签名一致且三家不全同。"""
    from gramfuzz.cluster import _pdiff

    def pred(tmap: dict) -> bool:
        vals = [tmap.get(p) for p in ("python", "go", "node")]
        if any(v is None for v in vals):
            return False
        feats = tuple(_pdiff({p: v for p, v in
                              zip(("python", "go", "node"), vals)}))
        return feats == tuple(fam_feats) and len(set(vals)) > 1

    return pred


def x_predicate(shape: dict):
    """X 谓词：四验证器文件级判定形态与族签名一致。"""

    def pred(statuses: dict) -> bool:
        return (isinstance(statuses, dict)
                and all(statuses.get(k) == v for k, v in shape.items())
                and set(statuses.keys()) == set(shape.keys()))

    return pred


# ---- wave 驱动 ----

def run_waves(states: list, work: Path, track: str,
              max_waves: int = 600, step_cap: int = 800) -> None:
    """每波：全部活跃族的当前试验集一次性写盘 → 探针/验证器批跑一次 → 推进。"""
    wave = 0
    while True:
        active = [s for s in states if not s.done and s.failed is None]
        if not active:
            break
        wave += 1
        if wave > max_waves:
            for s in active:
                s.failed = "wave cap (%d)" % max_waves
            break
        trial_meta = {}   # stem -> (state, tid)
        payloads = {}     # stem -> bytes
        for s in active:
            if s.steps > step_cap:
                s.failed = "step cap (%d)" % step_cap
                continue
            for tid, kind, meta, payload in s.next_trials():
                stem = "%s__t%d" % (s.fam_id, tid)
                trial_meta[stem] = (s, tid)
                payloads[stem] = s.trial_bytes(kind, meta, payload)
        if not payloads:
            break
        wdir = work / ("wave-%04d" % wave)
        wdir.mkdir(parents=True, exist_ok=True)
        for stem, content in payloads.items():
            (wdir / (stem + ".eml")).write_bytes(content)
        if track == "p":
            ev_dir = "/evidence/%s/confirm/work/%s/%s" % (RUN_W5, work.name, wdir.name)
            data = parser_probe_dir(wdir, ev_dir)
        else:
            ev_files = ["/evidence/%s/confirm/work/%s/%s/%s.eml"
                        % (RUN_W5, work.name, wdir.name, stem)
                        for stem in payloads]
            data = verifier_batch(ev_files)
            data = {Path(k).stem: v for k, v in data.items()}
        for s in active:
            if s.failed or not s.trials:
                continue
            results = {}
            for tid, *_ in s.trials:
                stem = "%s__t%d" % (s.fam_id, tid)
                results[tid] = bool(s.pred(data.get(stem)))
            s.advance(results)
        shutil.rmtree(wdir, ignore_errors=True)
        if wave % 10 == 0:
            print("  wave %d: done=%d/%d failed=%d"
                  % (wave, sum(1 for s in states if s.done),
                     len(states), sum(1 for s in states if s.failed)), flush=True)


# ---- 上下文 ----

def load_context(w4_stage: Path, confirm: Path) -> list[dict]:
    """families.json（mech 操作版）+ stage2 + corpus-index → 族上下文表。"""
    fam_doc = json.loads((confirm / "families.json").read_text(encoding="utf-8"))
    rows = {r["case"]: r for r in json.loads(
        (w4_stage / "stage2.json").read_text(encoding="utf-8"))}
    index = {i["case"]: i for i in json.loads(
        (w4_stage / "corpus-index.json").read_text(encoding="utf-8"))}
    fams = []
    for f in fam_doc["families"]:
        rep = f["representative"]
        key = f["key"]
        fams.append({
            "family": rep,
            "key": key,
            "members": f["members"], "n": f["n"],
            "series_union": f["series_union"],
            "entry": index[rep]["entry"], "op": index[rep]["op"],
            "p_feats": tuple(key[2]),
            "preserved": {t: v for t, v in key[3]},
            "x_shape": {k: v for k, v in key[4] if not str(k).endswith("@postfix")},
            "dshape": key[5],
            "views_w4": rows[rep]["views"],
            "verdicts_w4": rows[rep].get("verdicts") or {},
            "corpus_eml": w4_stage / "corpus" / ("%s.eml" % rep),
            "sign_eml": w4_stage / "sign" / ("%s-sign.eml" % rep),
        })
    return fams


# ---- phase: sanity（谓词在未缩减代表上必须可重放；KB2 锚是硬门） ----

def phase_sanity(w4_stage: Path, confirm: Path) -> dict:
    fams = load_context(w4_stage, confirm)
    deliver_probes()
    work = confirm / "work"
    work.mkdir(parents=True, exist_ok=True)
    # P：全部代表 corpus 文件过三 parser，对照 w4 stage2 的 views（精确元组）
    sdir = work / "sanity"
    if sdir.exists():
        shutil.rmtree(sdir)
    sdir.mkdir(parents=True)
    for f in fams:
        shutil.copy(f["corpus_eml"], sdir / f["corpus_eml"].name)
    data = parser_probe_dir(sdir, "/evidence/%s/confirm/work/sanity" % RUN_W5)
    p_ok, p_tuple_mismatch, p_feat_mismatch = {}, [], []
    for f in fams:
        tmap = data.get(f["family"])
        w4 = {k: tuple(v) for k, v in f["views_w4"].items()}
        replay = {k: tmap[k] if tmap else None for k in ("python", "go", "node")}
        exact_ok = replay == w4
        pred = p_predicate(f["p_feats"])
        pred_ok = tmap is not None and pred(tmap)
        p_ok[f["family"]] = exact_ok and pred_ok
        if not exact_ok:
            p_tuple_mismatch.append({"family": f["family"], "w4": f["views_w4"],
                                     "replay": {k: list(v) if v else None
                                                for k, v in replay.items()}})
        if not pred_ok:
            p_feat_mismatch.append({"family": f["family"],
                                    "feats": list(f["p_feats"])})
    # X：31 个 X 族代表 sign 文件 + KB2 锚，四验证器重放对照 stage2 file 级判定
    xfams = [f for f in fams if "X" in f["series_union"]]
    ev_files = ["/evidence/%s/gramfuzz/sign/%s-sign.eml" % (RUN_W4, f["family"])
                for f in xfams]
    anchor_ev = "/evidence/%s/gramfuzz/sign/gf-sign-anchor-kb2.eml" % RUN_W4
    vdata = verifier_batch(ev_files + [anchor_ev])
    x_ok, x_mismatch = {}, []
    for f in xfams:
        key = "/evidence/%s/gramfuzz/sign/%s-sign.eml" % (RUN_W4, f["family"])
        got = {k: v for k, v in (vdata.get(key) or {}).items()}
        want = f["x_shape"]
        ok = got == want
        x_ok[f["family"]] = ok
        if not ok:
            x_mismatch.append({"family": f["family"], "want": want, "got": got})
    anchor = vdata.get(anchor_ev) or {}
    anchor_ok = all(anchor.get(k) == v for k, v in KB2_EXPECT.items())
    doc = {
        "p_checked": len(fams), "p_exact_and_pred_ok": sum(p_ok.values()),
        "p_ok_by_family": p_ok,
        "p_tuple_mismatch": p_tuple_mismatch, "p_feat_mismatch": p_feat_mismatch,
        "x_checked": len(xfams), "x_ok": sum(x_ok.values()),
        "x_ok_by_family": x_ok, "x_mismatch": x_mismatch,
        "kb2_anchor": {"file": "sign/gf-sign-anchor-kb2.eml",
                       "expect": KB2_EXPECT, "got": anchor, "ok": anchor_ok},
    }
    (confirm / "sanity.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    shutil.rmtree(sdir, ignore_errors=True)
    print("sanity: p %d/%d ok, x %d/%d ok, kb2 anchor %s"
          % (doc["p_exact_and_pred_ok"], len(fams), doc["x_ok"], len(xfams),
             "PASS" if anchor_ok else "FAIL"))
    if not anchor_ok:
        raise RuntimeError("KB2 正确性锚未复现（%s）——接线有误，停下修"
                           % json.dumps(anchor))
    return doc


# ---- phase: p（全部族 corpus 轨 ddmin） ----

def phase_p(w4_stage: Path, confirm: Path) -> dict:
    fams = load_context(w4_stage, confirm)
    sanity = json.loads((confirm / "sanity.json").read_text(encoding="utf-8"))
    reduced = confirm / "reduced"
    reduced.mkdir(parents=True, exist_ok=True)
    work = confirm / "work" / "p"
    work.mkdir(parents=True, exist_ok=True)
    states, by_fam = [], {}
    for f in fams:
        raw = f["corpus_eml"].read_bytes()
        st = FamState(f["family"], raw, p_predicate(f["p_feats"]), track="p")
        if not sanity.get("p_ok_by_family", {}).get(f["family"]):
            st.failed = "sanity: P replay mismatch on representative"
        states.append(st)
        by_fam[f["family"]] = (f, st)
    run_waves(states, work, track="p")
    # 终验：minimized 文件过三 parser，特征与族签名一致（批量一次）
    finals = [s for s in states if s.failed is None]
    fdir = work / "final"
    if fdir.exists():
        shutil.rmtree(fdir)
    fdir.mkdir(parents=True)
    for s in finals:
        out = s.candidate()
        (reduced / ("%s.eml" % s.fam_id)).write_bytes(out)
        (fdir / ("%s.eml" % s.fam_id)).write_bytes(out)
    data = parser_probe_dir(fdir, "/evidence/%s/confirm/work/p/final" % RUN_W5)
    results = {}
    for s in states:
        f, _ = by_fam[s.fam_id]
        rec = {"family": s.fam_id, "original_bytes": len(f["corpus_eml"].read_bytes()),
               "status": "failed" if s.failed else "done",
               "failure_reason": s.failed, "steps": s.steps}
        if s.failed is None:
            out = s.candidate()
            rec["minimized_bytes"] = len(out)
            rec["product"] = "reduced/%s.eml" % s.fam_id
            tmap = data.get(s.fam_id)
            rec["p_verify"] = bool(tmap and s.pred(tmap))
            rec["min_gen_block_hex"] = s.min_gen_block().hex()
            rec["status"] = "confirmed" if rec["p_verify"] else "failed"
            if not rec["p_verify"]:
                rec["failure_reason"] = "predicate drifted after ddmin"
        results[s.fam_id] = rec
    (confirm / "p-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    ok = sum(1 for r in results.values() if r["status"] == "confirmed")
    print("phase p: %d/%d families confirmed (minimized + predicate replay)"
          % (ok, len(results)))
    return results


# ---- phase: x（X 族 sign 轨 ddmin + KB2 锚最小子） ----

def phase_x(w4_stage: Path, confirm: Path) -> dict:
    fams = load_context(w4_stage, confirm)
    sanity = json.loads((confirm / "sanity.json").read_text(encoding="utf-8"))
    p_res = json.loads((confirm / "p-results.json").read_text(encoding="utf-8"))
    xfams = [f for f in fams if "X" in f["series_union"]]
    reduced = confirm / "reduced"
    reduced.mkdir(parents=True, exist_ok=True)
    work = confirm / "work" / "x"
    work.mkdir(parents=True, exist_ok=True)
    # P-min 种子跳表：P 轨缩完的幸存块若已呈族签名，直接作为 X 轨起点
    # （谓词不中则回退原件——记录 seed 用没用，供审计）。
    seeds = {}
    sdir = work / "seed"
    if sdir.exists():
        shutil.rmtree(sdir)
    sdir.mkdir(parents=True)
    for f in xfams:
        pr = p_res.get(f["family"], {})
        if pr.get("status") == "confirmed" and pr.get("min_gen_block_hex"):
            block = bytes.fromhex(pr["min_gen_block_hex"])
            _, frozen = x_frozen_split(f["sign_eml"].read_bytes())
            (sdir / ("%s.eml" % f["family"])).write_bytes(block + frozen)
            seeds[f["family"]] = block
    seed_v = {}
    if seeds:
        ev = ["/evidence/%s/confirm/work/x/seed/%s.eml" % (RUN_W5, fid)
              for fid in seeds]
        seed_v = {Path(k).stem: v for k, v in verifier_batch(ev).items()}
    states, by_fam = [], {}
    for f in xfams:
        raw = f["sign_eml"].read_bytes()
        seed_gen = None
        got = seed_v.get(f["family"]) or {}
        if seeds.get(f["family"]) and got and \
                all(got.get(k) == v for k, v in f["x_shape"].items()) and \
                set(got.keys()) == set(f["x_shape"].keys()):
            seed_gen = seeds[f["family"]]
        st = FamState(f["family"], raw, x_predicate(f["x_shape"]), track="x",
                      seed_gen=seed_gen)
        if not sanity.get("x_ok_by_family", {}).get(f["family"]):
            st.failed = "sanity: X replay mismatch on representative"
        states.append(st)
        by_fam[f["family"]] = (f, st, seed_gen is not None)
    # KB2 锚合成族：obs-Received 注入（w3 sigprobe2 KB2_INJECT，w4 sign 锚件）
    anchor_raw = (w4_stage / "sign" / "gf-sign-anchor-kb2.eml").read_bytes()
    anchor_st = FamState("gf-sign-anchor-kb2", anchor_raw,
                         x_predicate(KB2_EXPECT), track="x")
    states.append(anchor_st)
    by_fam["gf-sign-anchor-kb2"] = ({"x_shape": KB2_EXPECT,
                                     "sign_eml": w4_stage / "sign" / "gf-sign-anchor-kb2.eml"},
                                    anchor_st, False)
    run_waves(states, work, track="x")
    finals = [s for s in states if s.failed is None]
    fdir = work / "final"
    if fdir.exists():
        shutil.rmtree(fdir)
    fdir.mkdir(parents=True)
    for s in finals:
        out = s.candidate()
        (reduced / ("%s-sign.eml" % s.fam_id)).write_bytes(out)
        (fdir / ("%s-sign.eml" % s.fam_id)).write_bytes(out)
    ev_files = ["/evidence/%s/confirm/work/x/final/%s-sign.eml" % (RUN_W5, s.fam_id)
                for s in finals]
    vdata = verifier_batch(ev_files)
    results = {}
    for s in states:
        f, _, seeded = by_fam[s.fam_id]
        rec = {"family": s.fam_id, "original_bytes": len(f["sign_eml"].read_bytes()),
               "status": "failed" if s.failed else "done",
               "failure_reason": s.failed, "steps": s.steps,
               "seeded_from_p_min": seeded}
        if s.failed is None:
            out = s.candidate()
            rec["minimized_bytes"] = len(out)
            rec["product"] = "reduced/%s-sign.eml" % s.fam_id
            key = "/evidence/%s/confirm/work/x/final/%s-sign.eml" % (RUN_W5, s.fam_id)
            got = vdata.get(key) or {}
            rec["x_verify"] = bool(s.pred(got))
            rec["verdicts_replay"] = got
            rec["status"] = "confirmed" if rec["x_verify"] else "failed"
            if not rec["x_verify"]:
                rec["failure_reason"] = "verifier shape drifted after ddmin"
        results[s.fam_id] = rec
    ok = sum(1 for r in results.values() if r["status"] == "confirmed")
    anchor_rec = results.get("gf-sign-anchor-kb2", {})
    print("phase x: %d/%d confirmed; kb2 anchor minimal: %s (%s)"
          % (ok, len(results),
             anchor_rec.get("product"),
             "PASS" if anchor_rec.get("x_verify") else "FAIL"))
    if anchor_rec.get("status") != "confirmed":
        raise RuntimeError("KB2 锚最小子谓词重放未过——谓词导出有错，停下修")
    # 机制约束锚：无约束 ddmin 会把注入行缩成任意非头行（实测单字节 "0" 即可
    # 呈同一判定形态——更广的触发类，记为观察）；任务要求的 KB2 锚是
    # obs-Received 注入的最小子，冻结 "Received" 名字前缀重缩。
    anchor_constrained = _anchor_constrained(w4_stage, confirm, work)
    anchor_variants = _anchor_variants(w4_stage, confirm, work)
    results["gf-sign-anchor-kb2"]["unconstrained_observation"] = (
        "无约束最小子把注入行缩到非头行仍呈同一形态（dkimpy 对签名上方任意"
        "非头行 parse-error 的更广触发类）；约束锚见 constrained_minimized_bytes")
    results["gf-sign-anchor-kb2"]["constrained_minimized_bytes"] = \
        anchor_constrained["minimized_bytes"]
    results["gf-sign-anchor-kb2"]["constrained_gen_block_hex"] = \
        anchor_constrained["gen_block"].hex()
    results["gf-sign-anchor-kb2"]["constrained_x_verify"] = \
        anchor_constrained["x_verify"]
    results["gf-sign-anchor-kb2"]["constrained_verdicts_replay"] = \
        anchor_constrained["verdicts_replay"]
    results["gf-sign-anchor-kb2"]["anchor_variants"] = anchor_variants
    (confirm / "x-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    if not anchor_constrained["x_verify"]:
        raise RuntimeError("约束 KB2 锚最小子谓词重放未过——停下修")
    return results


def _anchor_constrained(w4_stage: Path, confirm: Path, work: Path) -> dict:
    """KB2 锚的机制约束最小化：冻结 "Received :"（名字 + obs 冒号）10 字节，
    其余（值区）逐删。

    变体实测（x-results.json 的 anchor_variants）：无冒号行 / obs 冒号行都呈
    KB2 形态，严格 `Received:` 使 dkimpy 翻 pass——obs 冒号位移是承载字节。
    """
    raw = (w4_stage / "sign" / "gf-sign-anchor-kb2.eml").read_bytes()
    gen, frozen = x_frozen_split(raw)
    block = gen[:-2] if gen.endswith(b"\r\n") else gen   # 不动结尾 CRLF
    prefix = len(b"Received :")
    pred = x_predicate(KB2_EXPECT)
    rounds = 0
    while True:
        rounds += 1
        cands = []
        for i in range(prefix, len(block)):
            cands.append(block[:i] + block[i + 1:])
        if not cands:
            break
        adir = work / ("anchor-%02d" % rounds)
        adir.mkdir(parents=True, exist_ok=True)
        for j, cand in enumerate(cands):
            (adir / ("a%03d.eml" % j)).write_bytes(cand + b"\r\n" + frozen)
        ev = ["/evidence/%s/confirm/work/x/%s/a%03d.eml" % (RUN_W5, adir.name, j)
              for j in range(len(cands))]
        vdata = verifier_batch(ev)
        applied = False
        for j, cand in enumerate(cands):
            got = vdata.get(ev[j]) or {}
            if pred(got):
                block = cand
                applied = True
                break
        shutil.rmtree(adir, ignore_errors=True)
        if not applied:
            break
    final = block + b"\r\n" + frozen
    (confirm / "reduced" / "gf-sign-anchor-kb2-sign.eml").write_bytes(final)
    fdir = work / "anchor-final"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "anchor.eml").write_bytes(final)
    vdata = verifier_batch(["/evidence/%s/confirm/work/x/anchor-final/anchor.eml"
                            % RUN_W5])
    got = vdata.get("/evidence/%s/confirm/work/x/anchor-final/anchor.eml" % RUN_W5) or {}
    return {"minimized_bytes": len(final), "gen_block": block + b"\r\n",
            "x_verify": pred(got), "verdicts_replay": got}


def _anchor_variants(w4_stage: Path, confirm: Path, work: Path) -> dict:
    """锚形态触发面的手工变体矩阵（obs 冒号位移是承载字节的直接证据）。"""
    raw = (w4_stage / "sign" / "gf-sign-anchor-kb2.eml").read_bytes()
    _, frozen = x_frozen_split(raw)
    variants = {
        "Received-alone": b"Received\r\n",
        "Received-obs-colon-empty": b"Received :\r\n",
        "Received-strict-colon-empty": b"Received:\r\n",
        "Received-obs-colon-full": b"Received : from x by y; Sat, 3 Oct 2026 00:00:00 +0000\r\n",
        "junk-line-X": b"X\r\n",
        "space-continuation": b" \r\n",
    }
    d = work / "anchor-variants"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for name, blk in variants.items():
        (d / (name + ".eml")).write_bytes(blk + frozen)
    ev = ["/evidence/%s/confirm/work/x/anchor-variants/%s.eml" % (RUN_W5, n)
          for n in variants]
    vdata = verifier_batch(ev)
    pred = x_predicate(KB2_EXPECT)
    out = {}
    for name, e in zip(variants, ev):
        got = vdata.get(e) or {}
        out[name] = {"gen_block": variants[name].rstrip(b"\r\n").decode("latin1"),
                     "verdicts": {k: got.get(k)
                                  for k in ("dkimpy", "perl", "go", "rspamd")},
                     "kb2_shape": pred(got)}
    return out


# ---- phase: relay（T 批量收尾 + D 批量收尾；手术-执行-回滚，finally 保回滚） ----

_SURGERY_APPLY = [
    ("exim", ["docker", "exec", "exim", "sed", "-i",
              "s|route_list = \\* msl-auth-postfix byname|route_list = * msl-mailpit byname|",
              "/etc/exim4/exim4.conf"]),
    ("exim", ["docker", "exec", "exim", "sed", "-i",
              "s|  port = 25|  port = 1025|", "/etc/exim4/exim4.conf"]),
    ("exim", ["docker", "restart", "exim"]),
    ("opensmtpd", ["docker", "exec", "opensmtpd", "sed", "-i",
                   "s|relay host smtp://msl-auth-postfix:25|relay host smtp://msl-mailpit:1025|",
                   "/etc/smtpd.conf"]),
    ("opensmtpd", ["docker", "restart", "opensmtpd"]),
    ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "postconf", "-e",
                          "transport_maps = hash:/etc/postfix/transport"]),
    ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "postmap",
                          "/etc/postfix/transport"]),
    ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "postfix", "reload"]),
]

_SURGERY_ROLLBACK = [
    ("exim", ["docker", "exec", "exim", "sed", "-i",
              "s|route_list = \\* msl-mailpit byname|route_list = * msl-auth-postfix byname|",
              "/etc/exim4/exim4.conf"]),
    ("exim", ["docker", "exec", "exim", "sed", "-i",
              "s|  port = 1025|  port = 25|", "/etc/exim4/exim4.conf"]),
    ("exim", ["docker", "restart", "exim"]),
    ("opensmtpd", ["docker", "exec", "opensmtpd", "sed", "-i",
                   "s|relay host smtp://msl-mailpit:1025|relay host smtp://msl-auth-postfix:25|",
                   "/etc/smtpd.conf"]),
    ("opensmtpd", ["docker", "restart", "opensmtpd"]),
    ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "postconf", "-e",
                          "transport_maps ="]),
    ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "postfix", "reload"]),
]


def _surgery(steps, log):
    for target, cmd in steps:
        rc, out, err = sh(cmd, timeout=180)
        log.append({"target": target, "cmd": " ".join(cmd[2:]), "rc": rc,
                    "err": err.strip()[-200:]})
        if rc != 0:
            raise RuntimeError("surgery step failed: %s -> %s"
                               % (" ".join(cmd), err.strip()[-300:]))


def _rollback_check(log) -> list[str]:
    """回滚核对：三处配置的反向值都在 + 全部容器 Up。"""
    problems = []
    checks = [
        ("exim", ["docker", "exec", "exim", "grep", "-c",
                  "route_list = \\* msl-auth-postfix byname", "/etc/exim4/exim4.conf"], 1),
        ("opensmtpd", ["docker", "exec", "opensmtpd", "grep", "-c",
                       "relay host smtp://msl-auth-postfix:25", "/etc/smtpd.conf"], 1),
        ("msl-auth-postfix", ["docker", "exec", "msl-auth-postfix", "sh", "-c",
                              "postconf transport_maps | grep -c ."], 0),
    ]
    for target, cmd, want in checks:
        rc, out, err = sh(cmd, timeout=60)
        got = out.strip()
        log.append({"target": target, "check": " ".join(cmd[3:]), "rc": rc,
                    "out": got[:80]})
        # transport_maps 空值时 postconf 输出 "transport_maps =" 仍非空——按值判
        if target == "msl-auth-postfix":
            if "hash:/etc/postfix/transport" in got:
                problems.append("postfix transport_maps 未清干净: %s" % got)
        elif rc != 0 or got != str(want):
            problems.append("%s 回滚核对不符: rc=%d out=%r" % (target, rc, got))
    proc = subprocess.run(
        ["docker", "compose", "ps", "--format", "{{.Name}} {{.Status}}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
        cwd=str(_lab_root()))
    log.append({"target": "compose", "check": "docker compose ps",
                "rc": proc.returncode,
                "out": proc.stdout.decode("utf-8", "replace")[:600],
                "err": proc.stderr.decode("utf-8", "replace")[:200]})
    return problems


def _lab_root() -> Path:
    from gramfuzz.lab import MAILSECLAB_ROOT
    return MAILSECLAB_ROOT


def _control_letter(confirm: Path, target: str, server, port, log) -> bool:
    from gramfuzz.lab import diffrun
    case = "gf-w5-ctl-%s" % target
    raw = ("From: Control <ctl@lab.test>\r\nTo: capture@lab.test\r\n"
           "Date: Sat, 3 Oct 2026 23:59:00 +0000\r\nSubject: %s\r\n"
           "Message-ID: <%s@lab.test>\r\nX-Case-ID: %s\r\n\r\ncontrol\r\n"
           % (case, case, case)).encode()
    tdir = confirm / "relay-verify" / target
    tdir.mkdir(parents=True, exist_ok=True)
    ev_t = "/evidence/%s/confirm/relay-verify/%s" % (RUN_W5, target)
    r = diffrun.smtp_arm(tdir, ev_t, case, target, server, port, raw, "control")
    log.append({"target": target, "case": case, "smtp": r.get("smtp"),
                "captured": r.get("captured")})
    return bool(r.get("captured"))


def _relay_one_min(confirm: Path, fam_id: str, target: str, server, port,
                   raw: bytes, min_gen: bytes, problems: list) -> dict:
    """最小子过一台中继（funnel._relay_one 同款：smtp_arm + 标记核对 + 存活）。"""
    from gramfuzz.funnel import RELAY_MARKERS, _RECOVERY_FETCH
    from gramfuzz.lab import diffrun
    tdir = confirm / "relay-verify" / target
    tdir.mkdir(parents=True, exist_ok=True)
    ev_t = "/evidence/%s/confirm/relay-verify/%s" % (RUN_W5, target)
    try:
        r = diffrun.smtp_arm(tdir, ev_t, fam_id, target, server, port, raw, "relay")
    except Exception as exc:
        problems.append("%s/%s: smtp_arm 异常 %s" % (fam_id, target, exc))
        return {"error": str(exc)}
    if not r.get("captured"):
        return r
    stored_path = tdir / ("%s.stored.raw" % fam_id)
    marker = RELAY_MARKERS[target]
    tries = 0
    while marker not in stored_path.read_bytes() and tries < 3:
        tries += 1
        time.sleep(1.5)
        got = None
        for _ in range(3):
            rc, out, _ = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                             fam_id, marker.decode(),
                             "%s/%s.stored.raw" % (ev_t, fam_id)],
                            timeout=120, stdin=_RECOVERY_FETCH.encode())
            if out.strip().startswith("OK"):
                got = stored_path.read_bytes()
                break
            time.sleep(1)
        if got is None:
            break
    stored = stored_path.read_bytes()
    if marker in stored:
        r["attribution"] = "ok" if tries == 0 else "ok-recovered"
        r["gen_preserved"] = (min_gen in stored) if min_gen else None
        if not min_gen:
            r["gen_preserved_note"] = "no reducible bytes survive; vacuous"
    else:
        r["attribution"] = "marker-missing"
        r["gen_preserved"] = None
        problems.append("%s/%s: 存档缺中继标记，gen_preserved=未知" % (fam_id, target))
    return r


def _d_classify(slot: str | None) -> str | None:
    if not slot:
        return "missing"
    if "missing_mailbox@missing_domain" in slot:
        return "placeholder"
    if "@syntax_error" in slot:
        return "syntax_error"
    return "other"


def phase_relay(w4_stage: Path, confirm: Path) -> dict:
    from gramfuzz.lab import diffrun
    from gramfuzz import funnel
    fams = load_context(w4_stage, confirm)
    p_results = json.loads((confirm / "p-results.json").read_text(encoding="utf-8"))
    targets, _ = diffrun.load_config()
    log = {"surgery": [], "control": [], "rollback": [], "problems": []}
    results = {}
    t_fams = [f for f in fams if "T" in f["series_union"]
              and p_results.get(f["family"], {}).get("status") == "confirmed"]
    d_fams = [f for f in fams if "D" in f["series_union"]
              and p_results.get(f["family"], {}).get("status") == "confirmed"]
    keepalive = None
    try:
        _surgery(_SURGERY_APPLY, log["surgery"])
        time.sleep(2)
        for target, (server, port) in targets.items():
            if not _control_letter(confirm, target, server, port, log["control"]):
                raise RuntimeError("控制信未捕获（%s）——手术未生效，停" % target)
        # 保活（SURGERY.md：防 Docker Desktop resource-saver 停机）
        keepalive = subprocess.Popen(
            ["bash", "-c", "while true; do docker exec msl-client true; sleep 15; done"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # T 批量：每族最小子 × 三台中继
        for f in t_fams:
            raw = (confirm / "reduced" / ("%s.eml" % f["family"])).read_bytes()
            min_gen = bytes.fromhex(p_results[f["family"]]["min_gen_block_hex"])
            per_target = {}
            for target, (server, port) in targets.items():
                row = _relay_one_min(confirm, f["family"], target, server, port,
                                     raw, min_gen, log["problems"])
                per_target[target] = row
                time.sleep(0.8)
            verdict = {}
            for target in targets:
                want = f["preserved"].get(target)
                row = per_target[target]
                if "error" in row:
                    verdict[target] = {"ok": False, "reason": row["error"]}
                elif want is None:
                    ok = not row.get("captured")
                    verdict[target] = {"ok": ok, "want": "not-captured",
                                       "smtp_code": row.get("smtp_code"),
                                       "captured": row.get("captured")}
                else:
                    ok = bool(row.get("captured")) and \
                        row.get("gen_preserved") is want
                    verdict[target] = {"ok": ok, "want": want,
                                       "got": row.get("gen_preserved"),
                                       "captured": row.get("captured"),
                                       "attribution": row.get("attribution")}
            results[f["family"]] = {"kind": "T", "targets": per_target,
                                    "verdict": verdict,
                                    "t_verify": all(v["ok"] for v in verdict.values())}
        # D 批量：最小子投 bob@（标准链进 Dovecot，不经 capture 路由）+ ENVELOPE
        imap_dir = confirm / "imap"
        imap_dir.mkdir(parents=True, exist_ok=True)
        accepted = []
        for f in d_fams:
            raw = (confirm / "reduced" / ("%s.eml" % f["family"])).read_bytes()
            (imap_dir / ("%s.eml" % f["family"])).write_bytes(raw)
            rc, out, err = sh([
                "docker", "exec", "msl-client", "python3",
                "/opt/research/lib/smtp_send.py",
                "--server", "msl-auth-postfix", "--port", "25",
                "--mail-from", "alice@lab.test", "--rcpt-to", "bob@lab.test",
                "--input", "/evidence/%s/confirm/imap/%s.eml" % (RUN_W5, f["family"]),
                "--transcript",
                "/evidence/%s/confirm/imap/%s.smtp.txt" % (RUN_W5, f["family"]),
            ], timeout=90)
            try:
                sent = json.loads(out)
            except json.JSONDecodeError:
                sent = {"accepted": False, "raw": (out or err)[-200:]}
            # D 族多为 T+D 链：记录可能与 T 结果同键共存（setdefault 不覆盖）
            rec = results.setdefault(f["family"], {"kind": "D"})
            if rec.get("kind") == "T":
                rec["kind"] = "T+D"
            rec["smtp"] = sent.get("reply", "")[:60]
            if sent.get("accepted"):
                accepted.append(f["family"])
            else:
                rec["d_verify"] = False
                rec["d_reason"] = "smtp not accepted: %s" % sent.get("reply", "")[:80]
            time.sleep(0.8)
        if accepted:
            rc, out, err = sh(["docker", "exec", "-i", "msl-client", "python3", "-",
                               json.dumps(accepted)], timeout=600,
                              stdin=funnel._IMAP_PROBE_FETCH.encode())
            try:
                fetched = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
            except (json.JSONDecodeError, IndexError):
                fetched = {"_conn_error": (out or err)[-300:]}
            import base64
            for fam_id in accepted:
                f = next(x for x in d_fams if x["family"] == fam_id)
                rec = results[fam_id]
                frec = fetched.get(fam_id) or {}
                rec["imap_locator"] = frec.get("locator")
                env_parts = [base64.b64decode(p)
                             for p in frec.get("envelope_parts") or []]
                env = funnel._envelope_from_slot(env_parts)
                slot = env.get("from_slot")
                got = _d_classify(slot)
                rec["envelope_from"] = slot
                rec["dshape_got"] = got
                rec["dshape_want"] = f["dshape"]
                rec["d_verify"] = got == f["dshape"] and frec.get("uid") is not None
                if not rec["d_verify"]:
                    rec["d_reason"] = "dshape %r != %r (locator=%s)" % (
                        got, f["dshape"], frec.get("locator"))
                body_parts = [base64.b64decode(p)
                              for p in frec.get("body_parts") or []]
                if body_parts:
                    raw_stored = funnel._body_from_parts(body_parts)
                    (imap_dir / ("%s.stored.raw" % fam_id)).write_bytes(raw_stored)
    finally:
        if keepalive:
            keepalive.terminate()
        _surgery(_SURGERY_ROLLBACK, log["rollback"])
        log["rollback_problems"] = _rollback_check(log["rollback"])
    ok_t = sum(1 for r in results.values()
               if r.get("kind") in ("T", "T+D") and r.get("t_verify"))
    # D 计数按族不按 kind 标签（T+D 链的记录带 d 字段）
    ok_d = sum(1 for f in d_fams if (results.get(f["family"]) or {}).get("d_verify"))
    doc = {"log": log, "results": results,
           "t_families": len(t_fams), "t_ok": ok_t,
           "d_families": len(d_fams), "d_ok": ok_d,
           "rollback_clean": not log.get("rollback_problems")}
    (confirm / "relay-results.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("phase relay: T %d/%d ok, D %d/%d ok, rollback %s"
          % (ok_t, len(t_fams), ok_d, len(d_fams),
             "clean" if doc["rollback_clean"] else "PROBLEMS: %s"
             % log.get("rollback_problems")))
    return doc


# ---- phase: report（reduce-report.json：每族谓词定义、最小子、验证结果） ----

def phase_report(w4_stage: Path, confirm: Path) -> dict:
    fams = load_context(w4_stage, confirm)
    sanity = json.loads((confirm / "sanity.json").read_text(encoding="utf-8"))
    p_res = json.loads((confirm / "p-results.json").read_text(encoding="utf-8"))
    x_res = json.loads((confirm / "x-results.json").read_text(encoding="utf-8"))
    relay_path = confirm / "relay-results.json"
    relay = json.loads(relay_path.read_text(encoding="utf-8")) if relay_path.exists() else None
    out = []
    for f in fams:
        fam_id = f["family"]
        pr = p_res.get(fam_id, {})
        has_x = "X" in f["series_union"]
        xr = x_res.get(fam_id, {}) if has_x else {}
        entry = {
            "family": fam_id,
            "mech_key": f["key"],
            "n_members": f["n"], "members": f["members"],
            "series_union": f["series_union"],
            "entry": f["entry"], "op": f["op"],
            "predicate": {
                "p": {"kind": "三 parser 元组差分重放（python email / Go net/mail "
                              "/ Node mailparser 批量探针，funnel._tuple 同口径）",
                      "signature_features": list(f["p_feats"]),
                      "rule": "重放特征 == 族特征 且 三家元组不全同"},
            },
            "original_bytes": pr.get("original_bytes"),
            "minimized_bytes": pr.get("minimized_bytes"),
            "product": pr.get("product"),
            "p_verify": pr.get("p_verify"),
            "failure_reason": pr.get("failure_reason"),
        }
        if has_x:
            entry["predicate"]["x"] = {
                "kind": "四验证器文件级判定形态重放（verify_one.py 同仪器）",
                "signature_shape": f["x_shape"],
                "keep": "DKIM-Signature 及已签模板冻结（s2 注入结构）"}
            entry["sign_original_bytes"] = xr.get("original_bytes")
            entry["sign_minimized_bytes"] = xr.get("minimized_bytes")
            entry["sign_product"] = xr.get("product")
            entry["x_verify"] = xr.get("x_verify")
        checks = [entry["p_verify"]]
        if has_x:
            checks.append(entry.get("x_verify"))
        if "T" in f["series_union"] and relay:
            rr = relay["results"].get(fam_id) or {}
            entry["predicate"]["t"] = {
                "kind": "最小子过三台中继（SURGERY.md 捕获路由，批量收尾）",
                "signature": {t: f["preserved"].get(t) for t in f["preserved"]},
                "rule": "captured 与 gen 存活形态 == 族保留三元组"}
            entry["t_verify"] = rr.get("t_verify")
            drift = {}
            for t, v in (rr.get("verdict") or {}).items():
                if not v.get("ok"):
                    note = ((rr.get("targets") or {}).get(t) or {}).get(
                        "gen_preserved_note")
                    drift[t] = {"want": v.get("want"), "got": v.get("got"),
                                "captured": v.get("captured"),
                                "smtp_code": v.get("smtp_code"),
                                "vacuous": bool(note)}
            if drift:
                entry["t_drift"] = drift
            checks.append(entry.get("t_verify"))
        if "D" in f["series_union"] and relay:
            rr = relay["results"].get(fam_id) or {}
            entry["predicate"]["d"] = {
                "kind": "最小子投 bob@ + Dovecot ENVELOPE From 槽对照（批量收尾）",
                "signature": f["dshape"]}
            entry["d_verify"] = rr.get("d_verify")
            entry["dshape_got"] = rr.get("dshape_got")
            checks.append(entry.get("d_verify"))
        entry["status"] = "confirmed" if all(c is True for c in checks) else (
            "failed" if any(c is False for c in checks) else "incomplete")
        out.append(entry)
    anchor = x_res.get("gf-sign-anchor-kb2", {})
    relay_doc = None
    if relay:
        drift = {}
        for fam_id, rr in relay["results"].items():
            if rr.get("kind") != "T":
                continue
            for t, v in (rr.get("verdict") or {}).items():
                if not v.get("ok"):
                    key = "%s: want=%s got=%s" % (t, v.get("want"), v.get("got"))
                    drift[key] = drift.get(key, 0) + 1
        relay_doc = {"t_families": relay["t_families"], "t_ok": relay["t_ok"],
                     "d_families": relay["d_families"], "d_ok": relay["d_ok"],
                     "rollback_clean": relay["rollback_clean"],
                     "t_drift_directions": dict(sorted(drift.items(),
                                                       key=lambda x: -x[1]))}
    doc = {
        "run_w4": RUN_W4, "run_w5": RUN_W5,
        "interpretation_notes": {
            "t_drift": "T 漂移主因是 P 差分触发字节与中继改写触发字节基本独立"
                       "（如 P 最小子只剩单个 tab 行时 exim/postfix 无可改写、"
                       "osmtpd 拒收却普遍存活）——P 谓词 ddmin 会砍掉 T6 类改写"
                       "触发字节。漂移族按任务纪律记 failed，不硬凑。",
            "vacuous_gen": "min_gen 为空的族（P 差分落在 keep 行突变上）"
                           "gen 存活判据空转，t_drift 里标 vacuous=true。"},
        "clustering": json.loads((confirm / "families.json")
                                 .read_text(encoding="utf-8"))["lineage"],
        "sanity": {"p_exact_and_pred_ok": sanity["p_exact_and_pred_ok"],
                   "p_checked": sanity["p_checked"],
                   "x_ok": sanity["x_ok"], "x_checked": sanity["x_checked"],
                   "kb2_anchor": sanity["kb2_anchor"]},
        "kb2_anchor_minimal": {
            "family": "gf-sign-anchor-kb2",
            "mechanism": "obs-Received（`Received :`）注入于已签 DKIM-Signature 之上",
            "predicate_shape": KB2_EXPECT,
            "product": anchor.get("product"),
            "original_bytes": anchor.get("original_bytes"),
            "unconstrained_minimized_bytes": anchor.get("minimized_bytes"),
            "unconstrained_observation": anchor.get("unconstrained_observation"),
            "constrained_minimized_bytes": anchor.get("constrained_minimized_bytes"),
            "constrained_gen_block": (
                bytes.fromhex(anchor["constrained_gen_block_hex"]).decode("latin1")
                if anchor.get("constrained_gen_block_hex") else None),
            "constrained_x_verify": anchor.get("constrained_x_verify"),
            "constrained_verdicts_replay": anchor.get("constrained_verdicts_replay"),
            "anchor_variants": anchor.get("anchor_variants")},
        "relay": relay_doc,
        "families": out,
        "counts": {
            "families": len(out),
            "confirmed": sum(1 for e in out if e["status"] == "confirmed"),
            "failed": sum(1 for e in out if e["status"] == "failed"),
            "incomplete": sum(1 for e in out if e["status"] == "incomplete"),
            "p_confirmed": sum(1 for e in out if e.get("p_verify") is True),
            "x_families": sum(1 for e in out if "x_verify" in e),
            "x_confirmed": sum(1 for e in out if e.get("x_verify") is True),
            "t_families": sum(1 for e in out if "t_verify" in e),
            "t_confirmed": sum(1 for e in out if e.get("t_verify") is True),
            "d_families": sum(1 for e in out if "d_verify" in e),
            "d_confirmed": sum(1 for e in out if e.get("d_verify") is True),
        },
    }
    (confirm / "reduce-report.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("phase report: %s" % json.dumps(doc["counts"]))
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("w4_stage", help="w4 gramfuzz 产物目录（stage2.json 等）")
    ap.add_argument("confirm", help="w5 confirm 产物目录")
    ap.add_argument("--phase", default="all",
                    choices=["sanity", "p", "x", "relay", "report", "all"])
    args = ap.parse_args(argv)
    w4_stage = Path(args.w4_stage)
    confirm = Path(args.confirm)
    confirm.mkdir(parents=True, exist_ok=True)
    order = ["sanity", "p", "x", "relay", "report"]
    phases = order if args.phase == "all" else [args.phase]
    for ph in phases:
        print("== phase %s ==" % ph, flush=True)
        if ph == "sanity":
            phase_sanity(w4_stage, confirm)
        elif ph == "p":
            phase_p(w4_stage, confirm)
        elif ph == "x":
            phase_x(w4_stage, confirm)
        elif ph == "relay":
            phase_relay(w4_stage, confirm)
        elif ph == "report":
            phase_report(w4_stage, confirm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
