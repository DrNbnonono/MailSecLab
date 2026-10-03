"""变异器：字节级 + 行级 + 引导算子，MIMEminer 式 (selector, operator, priority) 反馈。

行级算子对头块行操作（≈ MIMEminer 的节点级——头块的"节点"就是行/字段实例）。
引导算子把 recfuzz 已证明的热点固化成原语（obs 冒号、大小写、折叠、重复实例），
初始权重高于随机算子——引擎从已知盈利处起步，但不被它锁死（权重有界衰减）。
所有算子只作用于头区（第一个 CRLFCRLF 之前），不可作用时返回 None。
"""
from __future__ import annotations

import json
import random
import re
from collections.abc import Callable
from pathlib import Path

_FIELD = re.compile(rb"(?m)^[!-9;-~]+:")


def _zone_end(raw: bytes) -> int:
    i = raw.find(b"\r\n\r\n")
    return i if i >= 0 else len(raw)


def _lines(raw: bytes):
    end = _zone_end(raw)
    zone, body = raw[:end], raw[end:]
    return zone.split(b"\r\n"), body


def _rebuild(lines_, body: bytes) -> bytes:
    return b"\r\n".join(lines_) + body


# ---- 引导算子（已知热点） ----

def _before_colon(raw: bytes, rng, pad: bytes) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l)]
    if not idx:
        return None
    i = rng.choice(idx)
    colon = lines_[i].index(b":")
    lines_[i] = lines_[i][:colon] + pad + lines_[i][colon:]
    return _rebuild(lines_, body)


def _case_name(raw: bytes, rng) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l)]
    if not idx:
        return None
    i = rng.choice(idx)
    name = lines_[i][:lines_[i].index(b":")]
    flipped = bytes(b + 32 if 65 <= b <= 90 else b - 32 if 97 <= b <= 122 else b for b in name)
    lines_[i] = flipped + lines_[i][len(name):]
    return _rebuild(lines_, body)


def _fold_line(raw: bytes, rng) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l) and len(l) > 8]
    if not idx:
        return None
    i = rng.choice(idx)
    pos = rng.randint(8, len(lines_[i]) - 1)
    lines_[i] = lines_[i][:pos] + b"\r\n " + lines_[i][pos:]
    return _rebuild(lines_, body)


def _dup_line(raw: bytes, rng) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l)]
    if not idx:
        return None
    i = rng.choice(idx)
    lines_.insert(i, lines_[i])
    return _rebuild(lines_, body)


# ---- 随机算子 ----

def _flip(raw: bytes, rng) -> bytes | None:
    end = _zone_end(raw)
    if end < 1:
        return None
    i = rng.randrange(end)
    b = raw[i] ^ (1 << rng.randrange(8))
    return raw[:i] + bytes([b]) + raw[i + 1:]


def _ins(raw: bytes, rng) -> bytes | None:
    end = _zone_end(raw)
    i = rng.randrange(end + 1)
    ch = bytes([rng.choice(b" \t:;()<>@,\\\"[]")])
    return raw[:i] + ch + raw[i:]


def _del(raw: bytes, rng) -> bytes | None:
    end = _zone_end(raw)
    if end < 1:
        return None
    i = rng.randrange(end)
    return raw[:i] + raw[i + 1:]


def _ldup(raw: bytes, rng) -> bytes | None:
    return _dup_line(raw, rng)


def _ldel(raw: bytes, rng) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l)]
    if not idx:
        return None
    i = rng.choice(idx)
    del lines_[i]
    return _rebuild(lines_, body)


def _lmove(raw: bytes, rng) -> bytes | None:
    lines_, body = _lines(raw)
    idx = [i for i, l in enumerate(lines_) if _FIELD.match(l)]
    if len(idx) < 2:
        return None
    a, b_ = rng.sample(idx, 2)
    lines_[a], lines_[b_] = lines_[b_], lines_[a]
    return _rebuild(lines_, body)


GUIDED_OPS: dict[str, Callable] = {
    "guided.space-colon": lambda r, rng: _before_colon(r, rng, b" "),
    "guided.tab-colon": lambda r, rng: _before_colon(r, rng, b"\t"),
    "guided.case-name": _case_name,
    "guided.fold-line": _fold_line,
    "guided.dup-line": _dup_line,
}
BYTE_OPS: dict[str, Callable] = {"byte.flip": _flip, "byte.insert": _ins, "byte.delete": _del}
LINE_OPS: dict[str, Callable] = {"line.dup": _ldup, "line.del": _ldel, "line.move": _lmove}
ALL_OPS = {**BYTE_OPS, **LINE_OPS, **GUIDED_OPS}

DEFAULT_WEIGHTS = {
    **{k: 0.4 for k in BYTE_OPS},
    **{k: 0.8 for k in LINE_OPS},
    **{k: 2.0 for k in GUIDED_OPS},
}


class PriorityTable:
    """MIMEminer §4.3 的反馈：命中差分 → 权重×1.5（上限 8）；落空 → ×0.85（下限 0.05）。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.w = dict(DEFAULT_WEIGHTS)
        if path and Path(path).exists():
            self.w.update(json.loads(Path(path).read_text(encoding="utf-8")))

    def pick(self, rng: random.Random) -> str:
        return rng.choices(list(self.w), weights=list(self.w.values()))[0]

    def reward(self, op: str) -> None:
        self.w[op] = min(self.w[op] * 1.5, 8.0)
        self._save()

    def punish(self, op: str) -> None:
        self.w[op] = max(self.w[op] * 0.85, 0.05)
        self._save()

    def _save(self) -> None:
        if self.path:
            Path(self.path).write_text(json.dumps(self.w, indent=1), encoding="utf-8")


# ops=None 时共用的无持久化权重表：只在首次用到时构造一次，不在循环路径上
# 反复新建对象（带 path 的表每次 reward/punish 都有磁盘写，绝不能进循环）。
_SHARED_TABLE: PriorityTable | None = None


def _shared_table() -> PriorityTable:
    global _SHARED_TABLE
    if _SHARED_TABLE is None:
        _SHARED_TABLE = PriorityTable()
    return _SHARED_TABLE


def mutate(raw: bytes, rng: random.Random, ops: tuple[str, ...] | None = None,
           depth: int = 1) -> bytes | None:
    """连续 depth 次随机算子；任一步不可作用则返回 None。

    ops 传入时只在其中选——gramfuzz 的正常用法（算子已由调用方的 PriorityTable
    按权重选出）。ops 为 None 时从模块级共享表（无持久化路径）里 pick，供单测
    与交互使用。
    """
    out = raw
    table = None if ops else _shared_table()
    for _ in range(depth):
        op = rng.choice(ops) if ops else table.pick(rng)
        nxt = ALL_OPS[op](out, rng)
        if nxt is None:
            return None
        out = nxt
    return out
