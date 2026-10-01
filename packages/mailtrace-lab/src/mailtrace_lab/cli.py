import argparse
from pathlib import Path
import sys

from mailtrace.render import safe_text

from .models import CaptureInput, CaseSpec, MAX_ITEMS, MAX_MESSAGE_BYTES, SweepSpec
from .store import ExperimentStore


def read_bounded(path: Path, maximum=MAX_MESSAGE_BYTES):
    with path.open("rb") as file:
        raw = file.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("输入超过大小上限。")
    return raw


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(prog="mailtrace-lab", description="生成/差分实验自动归档原始邮件；不发送邮件、不判定 MTA 极限。")
    parser.add_argument("--store", type=Path, help="实验根目录；默认 MAILTRACE_EXPERIMENT_DIR 或启动目录/local-experiments")
    commands = parser.add_subparsers(dest="command", required=True)
    forge = commands.add_parser("forge", help="由 CaseSpec 生成并归档")
    forge.add_argument("case", type=Path)
    forge.add_argument("--sweep", type=Path, help="单变量扫描 SweepSpec JSON")
    diff = commands.add_parser("diff", help="按命令行给定顺序比较原始快照")
    diff.add_argument("files", nargs="+", type=Path)
    diff.add_argument("--capture-gap", action="store_true", help="标记所有相邻采集间可能存在缺口")
    reproduce = commands.add_parser("reproduce", help="核验并复现已有实验，保存为新 ID")
    reproduce.add_argument("experiment_id")
    args = parser.parse_args(argv)
    store = ExperimentStore(args.store)
    try:
        if args.command == "forge":
            case = CaseSpec.model_validate_json(read_bounded(args.case))
            sweep = SweepSpec.model_validate_json(read_bounded(args.sweep)) if args.sweep else None
            run = store.forge(case, sweep)
        elif args.command == "diff":
            if not 2 <= len(args.files) <= MAX_ITEMS:
                raise ValueError("比较须提供 2–20 份快照。")
            run = store.compare([CaptureInput(raw=read_bounded(path), label=path.name[:200], capture_gap=args.capture_gap) for path in args.files])
        else:
            run = store.reproduce(args.experiment_id)
    except (OSError, ValueError) as error:
        print(f"mailtrace-lab: {safe_text(str(error))}", file=sys.stderr)
        return 1
    print(run.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
