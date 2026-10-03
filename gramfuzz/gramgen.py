"""语法驱动生成器：从 Grammar 入口符号派生样本，组装成差分语料。

设计要点：
- 返回 str，用 latin-1 编码保证字节忠实（ABNF 数值终端就是八位组）。
- 深度超限后只允许"纯终结符 alt"，仍失败则该样本失败，外层换 seed 重试。
- rep 无上界（hi=None）由 rep_cap 截断；样本长度由 max_len 截断。
- build_message 把生成头放在模板 From/To/Date 之上（注入位，s2 模式）；
  生成 From 族时天然形成重复实例场景——这是特性不是缺陷。

与计划稿 Step 3.3 的三处实现级修正（其余逐字照抄；动机见各处注释）：
1. _ensure_core_rules：六份 RFC 文本全部按引用导入 RFC 5234 Appendix B.1
   核心规则（CRLF/ALPHA/DIGIT/SP/...），rfc/ 里没有任何一份重述它们。
   不补则一切顶层头规则（都以 CRLF 收尾）不可派生，gramgen 单测全灭。
   只填缺口、从不覆盖已有定义，与 abnf.py「先加载者优先」同语义。
2. generate_sample 额外拒绝裸 CR/LF 与内嵌空行样本：obs-qp 合法产出
   `\\`+LF 之类字节、尾部 [CFWS]×CRLF 可拼出 CRLFCRLF，两者都过不了
   corpus_check（F1 纪律），在任务 5 的 phase_corpus 里也会被整封丢弃——
   提前过滤只是不造废样本，不改变语料语义。
3. RNG 种子用字符串而不是元组：random.Random(tuple) 经 tuple hash 混入
   PYTHONHASHSEED 随机化的 str hash，跨进程不可复现；字符串种子走
   sha512，跨进程稳定（corpus 按 seed 重放依赖这一点）。
"""
from __future__ import annotations

import random

from gramfuzz.abnf import Grammar

_TEMPLATE = [
    "From: Bank Security <security@lab.test>",
    "To: bob@lab.test",
    "Date: Sat, 3 Oct 2026 23:30:00 +0000",
]

# RFC 5234 Appendix B.1 核心规则（协议常量，逐条照抄产生式）。
_CORE_ABNF = """
ALPHA  =  %x41-5A / %x61-7A
BIT    =  "0" / "1"
CHAR   =  %x01-7F
CR     =  %x0D
CRLF   =  CR LF
CTL    =  %x00-1F / %x7F
DIGIT  =  %x30-39
DQUOTE =  %x22
HEXDIG =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
HTAB   =  %x09
LF     =  %x0A
LWSP   =  *(WSP / CRLF WSP)
OCTET  =  %x00-FF
SP     =  %x20
VCHAR  =  %x21-7E
WSP    =  SP / HTAB
"""
_CORE_NAMES = [ln.split()[0] for ln in _CORE_ABNF.strip().splitlines()]


def _ensure_core_rules(g: Grammar) -> None:
    """rfc/ 的 RFC 文本全部按引用导入 RFC 5234 核心规则而不重述；
    缺谁补谁，绝不覆盖已有定义（例如 rfc6376 自带的 WSP/FWS 定义保留其版本）。"""
    missing = [n for n in _CORE_NAMES if n not in g.rules]
    if missing:
        g.add_text("\n".join(ln for ln in _CORE_ABNF.strip().splitlines()
                             if ln.split()[0] in missing))


def _crlf_clean(s: str) -> bool:
    """纯 CRLF 纪律：无裸 CR/LF（obs-qp 可产出），无内嵌空行（CRLFCRLF）。"""
    flat = s.replace("\r\n", "")
    return "\r" not in flat and "\n" not in flat and "\r\n\r\n" not in s


def _derive(g: Grammar, tok, rng: random.Random, out: list[str], depth: int,
            max_depth: int, max_len: int, rep_cap: int) -> bool:
    kind = tok[0]
    if kind == "lit":
        out.append(tok[1])
        return sum(map(len, out)) <= max_len
    if kind == "set":
        out.append(rng.choice(tok[1]))
        return True
    if kind in ("ref", "group"):
        if depth > max_depth + 4:
            return False
        if kind == "ref":
            rule = g.rules.get(tok[1])
            if rule is None:
                return False
            alts = rule.alts
            if depth >= max_depth:
                alts = [a for a in alts if all(t[0] in ("lit", "set") for t in a)] or alts
        else:
            alts = tok[1]
        alt = rng.choice(alts)
        return all(_derive(g, t, rng, out, depth + 1, max_depth, max_len, rep_cap)
                   for t in alt)
    if kind == "rep":
        _, lo, hi, inner = tok
        hi_eff = min(hi if hi is not None else lo + rep_cap, max(lo, rep_cap))
        done = 0
        for _ in range(rng.randint(lo, hi_eff)):
            if not _derive(g, inner, rng, out, depth, max_depth, max_len, rep_cap):
                return done >= lo
            done += 1
        return True
    raise ValueError(kind)


def generate_sample(g: Grammar, symbol: str, seed: int, *, max_depth: int = 14,
                    max_len: int = 6000, rep_cap: int = 3, attempts: int = 25) -> str | None:
    _ensure_core_rules(g)
    for attempt in range(attempts):
        rng = random.Random("%d/%s/%d" % (seed, symbol, attempt))
        out: list[str] = []
        if _derive(g, ("ref", symbol), rng, out, 0, max_depth, max_len, rep_cap):
            s = "".join(out)
            if s and len(s) <= max_len and "\x00" not in s and _crlf_clean(s):
                return s
    return None


def build_message(generated: bytes, case_id: str, position: str = "top") -> bytes:
    """generated：一或多个完整头行（规则自带结尾 CRLF）。position: top / bottom。"""
    gen = generated if generated.endswith(b"\r\n") else generated + b"\r\n"
    fixed = "\r\n".join([
        "Subject: %s" % case_id,
        "Message-ID: <%s@lab.test>" % case_id,
        "X-Case-ID: %s" % case_id,
    ]).encode()
    head = ("\r\n".join(_TEMPLATE) + "\r\n").encode()
    if position == "top":
        block = gen + head + fixed
    else:
        block = head + gen + fixed
    return block + b"\r\n\r\nPlease confirm the payment.\r\n"
