# MailTrace Core V0.1/V0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付离线 Python 核心库、可读 CLI 与 JSON 报告，使 MailSecLab 可直接导入并复用分析结果。

**Architecture:** 原始字节取证与 Python 语义解析并行保留；Received 和认证声明分别结构化，再由确定性规则生成 MailReport。CLI 仅负责读取文件与展示；不在首版实现 API、DNS、数据库或网页。

**Tech Stack:** Python 3.11+、标准库 email/ipaddress/hashlib/base64/argparse、Pydantic 2、pytest。

---

本计划供后续实现使用，当前任务是设计。上方英文提示来自 writing-plans 模板；本会话未提供这两个 superpowers 执行子技能，不以它们为包依赖，不申请安装。实现可在当前会话按任务顺序推进；是否委派由用户另行指定。

设计依据：[首版规格](../specs/2026-10-01-mailtrace-design.md)、[报告契约](../../contracts/report-v0.1.md)、[验收矩阵](../../testing/acceptance-v0.1.md)。

## 文件与责任

| 文件 | 责任 |
| --- | --- |
| packages/mailtrace-core/pyproject.toml | setuptools 包构建、mailtrace 命令入口、运行/开发依赖 |
| packages/mailtrace-core/src/mailtrace/__init__.py | 只导出 analyze、AnalysisOptions、MailReport |
| packages/mailtrace-core/src/mailtrace/models/report.py | 契约全部 Pydantic 模型，from 别名与日期序列化 |
| packages/mailtrace-core/src/mailtrace/parser/raw.py | 物理头区扫描、字段位置、原始字节保留 |
| packages/mailtrace-core/src/mailtrace/parser/message.py | email 解析、recognized 对齐、概要和缺陷 |
| packages/mailtrace-core/src/mailtrace/parser/address.py | 显示名/地址解码，不进行域名归属判断 |
| packages/mailtrace-core/src/mailtrace/parser/tokens.py | 注释/引号/字面量感知的分隔，供 Received 与认证解析复用 |
| packages/mailtrace-core/src/mailtrace/parser/received.py | from/by/with/id/for、IP、时间和部分解析状态 |
| packages/mailtrace-core/src/mailtrace/parser/auth_results.py | 认证子句、属性、Received-SPF 与签名元数据 |
| packages/mailtrace-core/src/mailtrace/analysis/route.py | 原顺序反转、跳 ID、计数与路径摘要 |
| packages/mailtrace-core/src/mailtrace/analysis/timestamp.py | 明确时区转换、延迟与负时间规则 |
| packages/mailtrace-core/src/mailtrace/analysis/loop.py | 已知连续路径的回返与重复边检测 |
| packages/mailtrace-core/src/mailtrace/analysis/anomalies.py | 稳定规则编排、重复字段/私网/链长/连续性 |
| packages/mailtrace-core/src/mailtrace/engine.py | 组合解析与规则，提供无副作用 analyze |
| packages/mailtrace-core/src/mailtrace/render.py | 可读报告与控制字符转义 |
| packages/mailtrace-core/src/mailtrace/cli.py | 文件上限、参数、错误码、JSON 输出 |
| tests/conftest.py | 合成 fixture 读取与测试辅助 |
| tests/samples/*.eml | 小体积合成样本，保留原始换行 |
| tests/test_models.py | 模型、别名、版本、JSON 契约 |
| tests/test_message.py | 原始证据、边界、重复、编码 |
| tests/received/test_received.py | Received 提取、日期、顺序 |
| tests/test_authentication.py | 多来源、注释/引号、未知结果 |
| tests/test_analysis.py | 规则证据、阈值、循环、IP 分类 |
| tests/test_engine.py | 公共入口与确定性、输入错误 |
| tests/test_cli.py | 子进程测试已安装入口、I/O 与流分离 |
| README.md / .gitignore | PowerShell 安装运行说明及忽略本地产物 |

模型的 Python 字段 `from_endpoint` 使用 `Field(alias="from")`。所有 JSON 导出显式 `by_alias=True`；不能依赖 Pydantic 默认别名行为。模块方法都返回数据，不打印日志。目录中的 parser/analysis/models 均提供 `__init__.py`。

## Task 1：可安装包与契约模型

- [ ] 创建 package 构建配置与最小公共导出；命令入口固定为 `mailtrace.cli:main`。
- [ ] 根据报告契约逐项定义模型。可变默认值使用 `Field(default_factory=list)`；未知字段报错，Pydantic 配置 `extra="forbid"`；verified 首版用 `Literal[False]`。
- [ ] 用完整设计示例验证模型、别名与完整 JSON 序列化，而不是只测试几个字段默认值。

测试文件 `tests/test_models.py` 的起始验证：

```python
import json
from pathlib import Path
from mailtrace import MailReport

ROOT = Path(__file__).resolve().parents[1]

def test_contract_example_roundtrips():
    data = json.loads((ROOT / "docs/contracts/report-v0.1.example.json").read_text(encoding="utf-8"))
    report = MailReport.model_validate(data)
    assert report.model_dump(mode="json", by_alias=True) == data
    assert "from" in report.model_dump(mode="json", by_alias=True)["route"][0]
    assert report.route[0].from_endpoint.hostname == "laptop.local"
```

- [ ] 执行 `.\.venv\Scripts\python.exe -m pytest tests/test_models.py -q`，先观察模型尚未存在的导入失败，再完成模型并确认通过。
- [ ] 提交 `feat: define installable core package and report contract`。

## Task 2：原始证据、Python 视图与概要

- [ ] 新增 raw.py：按物理行从头扫描，空行停止；维护字节偏移和行号；WSP 起始行接到前一字段；孤立续行或非法名形成 malformed 证据段。记录标准与 obsolete 候选，保留完整头区 Base64。
- [ ] 新增 message.py：只将头区传给 `BytesHeaderParser(policy=policy.default)`，捕获 msg.defects；raw_items 顺序与候选字段对齐；Python 停止点之后的字段一律 recognized=false。无法对齐时报告缺陷，不强行给身份字段赋值。
- [ ] 新增 address.py：从 recognized 字段解码显示名和 Subject，汇总地址列表，保留重复实例。Date/Subject 的第一条仅用于概要。
- [ ] 在 tests/samples 中复制合成 basic 设计语料，并加入以下两个边界测试。

```python
import base64
from mailtrace import analyze

def test_body_cannot_inject_route():
    raw = b"Subject: demo\r\n\r\nReceived: from fake by fake; nonsense\r\n"
    report = analyze(raw)
    assert report.route == []
    assert len(report.headers) == 1
    assert base64.b64decode(report.source.header_base64) == b"Subject: demo\r\n"

def test_obsolete_candidate_is_not_silently_lost():
    raw = b"Received : from a.example by b.example; Thu, 01 Oct 2026 12:00:00 +0000\r\nFrom: a@sender.example\r\n\r\n"
    report = analyze(raw)
    assert report.route_summary.candidate_received_count == 1
    assert report.route_summary.recognized_received_count == 0
    assert not report.headers[0].recognized
    assert report.message.from_addresses == []
    assert any(f.code == "HEADER_PARSER_DISAGREEMENT" for f in report.warnings)
```

- [ ] 运行 `python -m pytest tests/test_message.py -q`；增加 raw-roundtrip、编码、重复字段与 header-only 的验收案例。
- [ ] 提交 `feat: preserve raw header evidence and parser boundaries`。

## Task 3：Received 分段与结构化

- [ ] 新增 tokens.py 的有状态扫描器：跟踪括号深度、引号、转义、方括号；只在顶层识别关键字与分号。单次扫描线性运行，避免针对超长字段的回溯正则。
- [ ] 新增 received.py：识别 from/by 子句主机、方括号 IP、with/id/for 与日期；多个 IP 保留候选并不挑选唯一 source。字段无法完整读取时按契约生成 partial/unparsed。
- [ ] 先实现以下测试，再逐项补齐验收矩阵中的注释/IPv6/日期案例。

```python
from mailtrace import analyze

def test_partial_received_remains_in_route():
    report = analyze(b"Received: by mx.recipient.example with ESMTP\r\n\r\n")
    assert len(report.route) == 1
    assert report.route[0].by.hostname == "mx.recipient.example"
    assert report.route[0].timestamp is None
    assert report.route[0].parse_status == "partial"

def test_comment_does_not_create_fake_by_clause():
    raw = b"Received: from a.example (comment by fake.example; ignored) by b.example; Thu, 01 Oct 2026 12:00:00 +0000\r\n\r\n"
    hop = analyze(raw).route[0]
    assert hop.from_endpoint.hostname == "a.example"
    assert hop.by.hostname == "b.example"
    assert hop.timestamp_raw == "Thu, 01 Oct 2026 12:00:00 +0000"
```

- [ ] 运行 `python -m pytest tests/received/test_received.py -q`，确认任何 recognized Received 都占一跳。
- [ ] 提交 `feat: parse Received hops with evidence references`。

## Task 4：认证声明与签名证据

- [ ] 复用 tokens 的注释/引号状态，在顶层分号处切认证子句；提取 authserv-id、method/result、reason 与重复属性列表。未知方法与未知 result 保留。
- [ ] 对 SPF/DKIM/DMARC 分别生成 summary；无 assertion 为 unknown，单一已知状态 reported，多状态 mixed，仅未知状态 unrecognized。所有 verified=false、trust=unassessed。
- [ ] 独立收集 Received-SPF、DKIM d/s/a 标签、三类 ARC 头，不能转成主动认证结果。

```python
from mailtrace import analyze

def test_dkim_signatures_do_not_imply_pass():
    report = analyze(b"DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=design; b=AA==\r\n\r\n")
    assert report.authentication.summary.dkim.status == "unknown"
    assert report.authentication.dkim_signatures[0].domain == "sender.example"
    assert report.authentication.dkim_signatures[0].verified is False

def test_quoted_reason_and_mixed_dkim_are_retained():
    raw = b'Authentication-Results: mx.recipient.example; dkim=pass reason="a;b" header.d=one.example; dkim=fail header.d=two.example\r\n\r\n'
    report = analyze(raw)
    assert len(report.authentication.assertions) == 2
    assert report.authentication.assertions[0].reason == "a;b"
    assert report.authentication.summary.dkim.status == "mixed"
    assert all(a.verified is False for a in report.authentication.assertions)
```

- [ ] 运行 `python -m pytest tests/test_authentication.py -q`；补齐 nested-comment、duplicate-property、unknown-method 与 auth-none。
- [ ] 提交 `feat: retain authentication assertions without implying verification`。

## Task 5：路由、时间与异常

- [ ] route.py 反转 recognized Received 的原始列表，分配 route_index/hop_id；禁止以 timestamp 排序。统计候选/识别/完整数量。
- [ ] timestamp.py 处理 +0000/明确偏移/-0000，未知时区返回 null。相邻延迟保留负值；仅全链时间确定且至少两跳时产生 total。
- [ ] anomalies.py 按验收矩阵的固定 code 与排序规则编排发现；范围分类先识别 documentation/loopback/link-local，再识别 RFC1918/ULA，不能直接套 is_private。
- [ ] loop.py 仅连接已知相接的边；路径中断重置当前可连接段；独立检测重复边。相邻共享中继节点不构成回返。

```python
from pathlib import Path
from mailtrace import AnalysisOptions, analyze

ROOT = Path(__file__).resolve().parents[1]

def test_basic_route_order_and_delay():
    report = analyze((ROOT / "docs/contracts/basic-example.eml").read_bytes())
    assert [h.header_id for h in report.route] == ["header-002", "header-001"]
    assert report.route[0].delay_seconds is None
    assert report.route[1].delay_seconds == 17
    assert report.route_summary.total_observed_delay_seconds == 17
    assert all(h.route_index + h.received_index == 3 for h in report.route)

def test_long_chain_threshold_is_strictly_greater():
    header = b"Received: from a.example by b.example; Thu, 01 Oct 2026 12:00:00 +0000\r\n"
    codes_at_limit = {f.code for f in analyze(header * 2, options=AnalysisOptions(chain_limit=2)).warnings}
    codes_over_limit = {f.code for f in analyze(header * 3, options=AnalysisOptions(chain_limit=2)).warnings}
    assert "LONG_RECEIVED_CHAIN" not in codes_at_limit
    assert "LONG_RECEIVED_CHAIN" in codes_over_limit
```

- [ ] 运行 `python -m pytest tests/test_analysis.py tests/received -q`；覆盖时间负数、链路不连续、回返及文档地址不触发私网规则。
- [ ] 提交 `feat: analyze route timing and evidence-based anomalies`。

## Task 6：公共 analyze 入口

- [ ] engine.py 依次组合输入编码、raw scan、message parse、Received/auth 结构化、route 与规则；最终模型统一校验。不要在核心函数捕获所有 Exception 后返回空“成功”报告。
- [ ] analyze 的关键字参数与契约一致；TypeError/ValueError 的范围明确。库入口不依赖输入路径，不创建文件，不使用 DNS。

```python
import pytest
from mailtrace import analyze

def test_analysis_is_deterministic():
    raw = b"Subject: deterministic\r\n\r\n"
    first = analyze(raw).model_dump(mode="json", by_alias=True)
    second = analyze(raw).model_dump(mode="json", by_alias=True)
    assert first == second

def test_empty_and_wrong_type_are_explicit():
    with pytest.raises(ValueError):
        analyze(b"")
    with pytest.raises(TypeError):
        analyze(123)
```

- [ ] 运行 `python -m pytest tests/test_engine.py -q`；加入 text/bytes 除 input_kind 外一致的验证。
- [ ] 提交 `feat: expose deterministic offline analyze API`。

## Task 7：CLI、文本与 JSON

- [ ] cli.py 用 argparse 添加 analyze PATH、--json、--chain-limit；正整数参数非法返回 2。上限加 1 字节读取，I/O/空/超限返回 1。生成警告不改变成功退出码。
- [ ] render.py 展示四个区域；认证明确标记为声明；用于终端的文本转义 ESC、非换行控制字符与输入中的回车，不改报告证据。
- [ ] JSON 使用 `model_dump_json(by_alias=True, indent=2)`，stdout 只有 JSON，stderr 诊断；readable renderer 不参与 JSON 生成。

```python
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def test_json_cli_stdout_is_one_report():
    result = subprocess.run(
        [sys.executable, "-m", "mailtrace.cli", "analyze", str(ROOT / "docs/contracts/basic-example.eml"), "--json"],
        capture_output=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert data["schema_version"] == "0.1"
    assert data["route"][1]["delay_seconds"] == 17

def test_file_error_does_not_write_json(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "mailtrace.cli", "analyze", str(tmp_path / "absent.eml"), "--json"],
        capture_output=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr
```

- [ ] 运行 `python -m pytest tests/test_cli.py -q`，并通过真实安装后的 `mailtrace.exe` 验证 entry point，补齐恰好上限/超限/参数错误/终端控制符案例。
- [ ] 提交 `feat: add readable and JSON analysis commands`。

## Task 8：交付验证与文档

- [ ] README 说明边界：离线分析、声明不是主动验证、启发式不是漏洞判定；给出 PowerShell 安装与运行命令。
- [ ] .gitignore 仅忽略 .venv、__pycache__、.pytest_cache、构建产物与本地邮件；显式保留 tests/samples 中合成语料。不用全局 `*.eml` 无意隐藏 fixture。
- [ ] 从清洁虚拟环境安装包，执行一次全量 `python -m pytest tests -q`，确认 import/CLI 不要求 Node.js/API/数据库。
- [ ] 用设计合成输入生成真实输出；与契约示例比较，差异必须解释或修复，不能仅为通过测试更改设计期望。
- [ ] 检查 git diff --check，记录实际依赖版本和测试结果；将功能提交推送至 origin/tool/mailtrace，核对研究分支未变化。

## 规格覆盖核对

| 规格范围 | 任务 |
| --- | --- |
| 安装与报告契约 | 1、8 |
| 原始 bytes、头区/正文边界、重复、编码、Python 差异 | 2 |
| Received 子句、注释、IP、部分结果 | 3 |
| 认证、签名存在、ARC、多个来源 | 4 |
| 顺序、时区、延迟、循环、链长、私网、证据 | 5 |
| 可直接 import、确定性、输入错误、无联网 | 6 |
| 文本、JSON、大小上限、错误码、终端转义 | 7 |
| 合成语料与复现 | 每个任务的 tests、8 |

所有测试代码是实施时的行为起点，当前没有运行产品测试。API、Web、DNS 与数据库各在其版本阶段另写实现计划，避免让核心首版依赖尚未存在的应用。
