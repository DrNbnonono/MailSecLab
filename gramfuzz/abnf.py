"""ABNF 提取器：RFC 5234 风格规则文本 → 可执行文法（gramgen 的输入）。

    g = Grammar.load_files(["rfc/rfc5322.txt", "rfc/rfc8601.txt"])
    g.rules["obs-received"]        # Rule(name, alts=[[Token, ...], ...])

Token 五类：
  ("ref", name)            规则引用
  ("lit", text)            引号字面量（prose `<...>` 视为空串终结符）
  ("set", chars)           数值终端：范围展开为候选字符集
  ("group", alts)          括号组；[...] 选项解析为 rep(0, 1, group)
  ("rep", lo, hi, token)   重复，hi=None 表示无上界（生成时由 rep_cap 截断）

多份 RFC 合并进同一 Grammar（5321/8617 会跨文档引用 5322/6376 的规则）。
同名规则重复定义（非 =/ 增量）时保留先加载的并记入 conflicts；解析失败的
规则跳过——生成器遇到缺失 ref 自然失败该分支，不影响其他规则。
规则区之外的散文行可能被误认为规则（如正文里的 "x = 5"），这类假规则
不被任何入口符号引用，惰性无害。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# `:=` 是 RFC 822 风格（rfc2045 等旧文法）；按普通 `=` 对待。
# 8601 的 authserv-id = value 依赖 rfc2045 的 := 规则，不认则 authres 入口零样本。
_RULE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*(=/|=|:=)\s*(.*)$")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_NUM = re.compile(r"%(d|x)([0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)?(?:\.[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)?)*)")


class ABNFError(ValueError):
    pass


@dataclass
class Rule:
    name: str
    alts: list[list[tuple]] = field(default_factory=list)


def _strip_comment(line: str) -> str:
    out, inq = [], False
    for ch in line:
        if ch == '"':
            inq = not inq
        elif ch == ";" and not inq:
            break
        out.append(ch)
    return "".join(out)


class _Parser:
    def __init__(self, s: str) -> None:
        self.s, self.i = s, 0

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def parse_alts(self, stop: str = "") -> list[list[tuple]]:
        alts = [[]]
        while True:
            self.ws()
            if self.i >= len(self.s):
                break
            if stop and self.s[self.i] in stop:
                break
            if self.s[self.i] == "/":
                self.i += 1
                alts.append([])
                continue
            tok = self.parse_item()
            alts[-1].append(tok)
        return [a for a in alts if a] or [[]]

    def parse_item(self) -> tuple:
        self.ws()
        c = self.s[self.i]
        m = re.match(r"(\d+)?\*(\d+)?", self.s[self.i:])
        if m and m.group(0):
            self.i += len(m.group(0))
            lo = int(m.group(1)) if m.group(1) else 0
            hi = int(m.group(2)) if m.group(2) else None
            return ("rep", lo, hi, self.parse_item())
        m = re.match(r"\d+", self.s[self.i:])
        if m:
            n = int(m.group(0))
            # 精确重复（如 zone 的 4DIGIT）：match 作用于切片 self.s[self.i:]，
            # m.end() 是相对值，必须加回起点。计划原稿写作 self.i = m.end()，
            # 会使非 0 起点的精确重复把位置重置回 1，在 RFC 5322 zone 规则上
            # 死循环（test_rfc5322_core_rules_present 实测暴露，故修正）。
            self.i += m.end()
            return ("rep", n, n, self.parse_item())
        if c == '"':
            j = self.s.index('"', self.i + 1)
            lit = self.s[self.i + 1: j]
            self.i = j + 1
            return ("lit", lit)
        if c == "%":
            m = re.match(r'%(s|i)"([^"]*)"', self.s[self.i:])
            if m:
                # RFC 7405 字符串字面量（%s 大小写敏感 / %i 大小写不敏感）。
                # 生成语义：按书写形态取字面量；大小写变体交给 grammut 的 case 算子。
                # 8617 的 instance/seal-cv-tag 依赖此语法，缺失则 ARC 入口零样本。
                self.i += m.end()
                return ("lit", m.group(2))
            m = _NUM.match(self.s, self.i)
            if not m:
                raise ABNFError(f"bad % terminal at {self.i}")
            base = 10 if m.group(1) == "d" else 16
            self.i = m.end()
            toks = []
            for part in m.group(2).split("."):
                if "-" in part:
                    a, b = part.split("-", 1)
                    lo, hi = int(a, base), int(b, base)
                    if lo > hi or hi > 0x10FFFF:
                        raise ABNFError(f"bad range {part}")
                    toks.append(("set", "".join(chr(v) for v in range(lo, hi + 1))))
                else:
                    toks.append(("lit", chr(int(part, base))))
            return toks[0] if len(toks) == 1 else ("group", [toks])
        if c == "(":
            self.i += 1
            alts = self.parse_alts(stop=")")
            self.i += 1
            return ("group", alts)
        if c == "[":
            self.i += 1
            alts = self.parse_alts(stop="]")
            self.i += 1
            return ("rep", 0, 1, ("group", alts))
        if c == "<":
            j = self.s.index(">", self.i)
            self.i = j + 1
            return ("lit", "")        # prose：按空终结符处理
        m = _NAME.match(self.s, self.i)
        if m:
            self.i = m.end()
            return ("ref", m.group(0))
        raise ABNFError(f"unexpected {c!r} at {self.i}")


class Grammar:
    def __init__(self) -> None:
        self.rules: dict[str, Rule] = {}
        self.conflicts: list[str] = []

    @classmethod
    def load_files(cls, paths) -> "Grammar":
        g = cls()
        for p in paths:
            g.add_text(Path(p).read_text(encoding="utf-8", errors="replace"))
        return g

    def add_text(self, text: str) -> None:
        name, inc, parts = None, False, []
        for raw in text.splitlines():
            line = _strip_comment(raw).strip()
            if not line:
                self._flush(name, inc, parts)
                name, inc, parts = None, False, []
                continue
            m = _RULE.match(line)
            if m:
                self._flush(name, inc, parts)
                name, inc, parts = m.group(1), m.group(2) == "=/", [m.group(3)]
            elif name is not None:
                parts.append(line)
        self._flush(name, inc, parts)

    def _flush(self, name, inc, parts) -> None:
        if name is None or not parts:
            return
        try:
            alts = _Parser(" ".join(parts)).parse_alts()
        except (ABNFError, ValueError, IndexError):
            # IndexError：正文散文行如 `t = 1`（裸数字后到达串尾）在 parse_item
            # 越界；8601/6376/8617 全量加载时必触发，未捕获会击穿 load_files。
            return
        rule = self.rules.get(name)
        if rule is None:
            self.rules[name] = Rule(name, alts)
        elif inc:
            rule.alts.extend(alts)
        else:
            self.conflicts.append(name)
