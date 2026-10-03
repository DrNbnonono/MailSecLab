"""A3.Step1 规范条目索引：从七份 RFC 文本抽取 MUST/SHOULD/MUST NOT 句，编号入库。

输入：/mnt/e/Gramfuzz/rfc/rfc{5321,5322,2045,6376,6532,8601,8617}.txt（六份计划内 + 8617）
输出：JSON 数组，每条 {id, rfc, line_start, line_end, section, text}。

设计（相对计划稿的微调，均有实况依据）：
- 关键词必须独立成词（\b），避免 "Requirements" 一类误命中；排除
  "Requirements"、"REQUIRED" 作名词的用法按上下文保留（REQUIRED 在 RFC 2119
  语义里作 MUST 用，保留但标 keyword）。
- 句级拼接：关键词句常跨行。命中行起，向后拼接至句号/问号收尾（最多 3 行、
  总长 400 字符），跳过分页脚注/页眉（[Page N]、RFC NNNN 行、作者行、^L）。
- section 追踪：`^\d+(\.\d+)*\.?\s{2,}\S` 与 `^Appendix [A-Z]` 记当前节号，
  供 A3 判定时按节检索。
- line_start/line_end 是文件物理行号（1 起），审阅者按行号区间读原文即可核对。

用法：
  wsl bash -c "python3 /mnt/e/MailSecLab/received-lab/research/lib/normative_index.py \
      /mnt/e/MailSecLab/received-lab/results/research/w5-20261003a/confirm/normative-index.json"
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RFC_DIR = Path("/mnt/e/Gramfuzz/rfc")
RFC_NAMES = ("rfc5321", "rfc5322", "rfc2045", "rfc6376", "rfc6532", "rfc8601", "rfc8617")
KEYWORD_PAT = re.compile(r"\b(MUST NOT|SHALL NOT|REQUIRED|SHOULD NOT|SHOULD|MUST|SHALL)\b")
# RFC 2119 关键词误命中排除（普通名词用法）
EXCLUDE_PAT = re.compile(r"(?i)\b(requirements?|Section \d|RFC-\d+)\b[^.]{0,40}$")
SECTION_PAT = re.compile(r"^(\d+(?:\.\d+)*)\.?\s{2,}(\S.*)$")
APPENDIX_PAT = re.compile(r"^(Appendix [A-Z](?:\.\d+)*)\.?\s{2,}(\S.*)$")
# 分页噪声行（脚注/页眉/作者行）
NOISE_PAT = re.compile(r"^(\f|\[Page \d+\]|RFC \d{4}\s{4,}.*\S\s{4,}(October|November|December|January|February|March|April|May|June|July|August|September)\s+\d{4}|.*Standards Track\s+\[Page \d+\]|.*\S\s{8,}\[Page \d+\])")
MAX_QUOTE = 400


def _is_noise(line: str) -> bool:
    s = line.rstrip()
    if not s.strip():
        return False  # 空行不是噪声，但也不贡献文本
    if s.startswith("\f") or "[Page " in s:
        return True
    # 页眉形如 "RFC 5322                Internet Message Format             October 2008"
    if re.match(r"^RFC \d{4}\s", s) and re.search(r"\s{3,}(19|20)\d{2}\s*$", s):
        return True
    # 作者/类别行 "Resnick                     Standards Track"
    if re.search(r"\S\s{10,}(Standards Track|Informational|Experimental|Proposed Standard|Obsoletes|Category:)", s):
        return True
    return False


def extract(rfc_name: str) -> list[dict]:
    f = RFC_DIR / f"{rfc_name}.txt"
    # 只按 LF 切行（编辑器/sed 口径）。Path.read_text 的 universal newlines 与
    # str.splitlines 会把 \x0c 换页符也当行界，行号会漂移 +95（rfc5321 实测），
    # 违反「行号可核」纪律。
    lines = f.read_text(encoding="utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out = []
    section = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        m = SECTION_PAT.match(line)
        if m:
            section = m.group(1)
            i += 1
            continue
        ma = APPENDIX_PAT.match(line)
        if ma:
            section = ma.group(1)
            i += 1
            continue
        if KEYWORD_PAT.search(line) and not _is_noise(line):
            # 句级拼接：向后合并直到句子收尾
            start = i
            text = line.strip()
            end = i
            j = i
            # 先向前找句首（命中行可能从句子中段开始？RFC 排版句首常在行首）
            while len(text) < MAX_QUOTE:
                if re.search(r"[.?]\s*$", text) and len(text) > 20:
                    break
                j += 1
                if j >= len(lines) or j - start > 4:
                    break
                nxt = lines[j]
                if not nxt.strip() or _is_noise(nxt):
                    break
                text += " " + nxt.strip()
                end = j
            out.append({
                "rfc": rfc_name.upper(),
                "line_start": start + 1,
                "line_end": end + 1,
                "section": section,
                "keyword": KEYWORD_PAT.search(line).group(1),
                "text": text[:MAX_QUOTE],
            })
        i += 1
    # 编号
    for k, item in enumerate(out, 1):
        item["id"] = f"{rfc_name.upper()}-{k:04d}"
    return out


def main(out_path: str) -> int:
    index = []
    for name in RFC_NAMES:
        items = extract(name)
        print(f"{name.upper()}: {len(items)} statements")
        index.extend(items)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    print("total normative statements:", len(index), "->", out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
