import argparse
from pathlib import Path
import sys

from .engine import analyze
from .models.report import AnalysisOptions
from .render import render, safe_text

MAX_INPUT_BYTES = 10 * 1024 * 1024


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("必须提供正整数。") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("必须提供正整数。")
    return parsed


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(prog="mailtrace", description="离线邮件头分析；不主动验证邮件来源。")
    parser.add_argument("--version", action="version", version="MailTrace 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("analyze", help="分析 .eml 或邮件头文本文件")
    command.add_argument("path", type=Path)
    command.add_argument("--json", action="store_true", help="输出单个 JSON 报告")
    command.add_argument("--chain-limit", type=positive_int, default=50)
    args = parser.parse_args(argv)
    try:
        with args.path.open("rb") as file:
            raw = file.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("输入超过 10 MiB 上限。")
        report = analyze(raw, options=AnalysisOptions(chain_limit=args.chain_limit))
    except (OSError, ValueError) as exc:
        print(f"mailtrace: {safe_text(exc)}", file=sys.stderr)
        return 1
    print(report.model_dump_json(by_alias=True, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
