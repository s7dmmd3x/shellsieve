"""CLI sub-command: shellsieve lint — run lint mode across one or more files."""
from __future__ import annotations

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List

from shellsieve.linter import lint_files, LintReport
from shellsieve.config import load_config
from shellsieve.formatter import TextFormatter, JsonFormatter


def build_lint_parser(parent: ArgumentParser) -> ArgumentParser:
    p = parent.add_parser(
        "lint",
        help="Run lint checks and produce a structured report.",
    )
    p.add_argument("paths", nargs="+", type=Path, metavar="FILE", help="Scripts to lint.")
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="Print a summary line after the report.",
    )
    p.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit 0 even when issues are found.",
    )
    return p


def _print_report(report: LintReport, fmt: str, summary: bool) -> None:
    formatter = JsonFormatter() if fmt == "json" else TextFormatter()
    for file_result in report.results:
        if file_result.error:
            print(f"ERROR reading {file_result.path}: {file_result.error}", file=sys.stderr)
            continue
        if not file_result.ok:
            from shellsieve.scanner import ScanResult
            sr = ScanResult(path=file_result.path, matches=file_result.matches)
            print(formatter.format(sr), end="")

    if summary:
        d = report.as_dict()
        print(
            f"\nSummary: {d['total_files']} file(s) scanned, "
            f"{d['failed_files']} with issues, "
            f"{d['total_errors']} error(s), "
            f"{d['total_warnings']} warning(s)."
        )


def run_lint(args: Namespace) -> int:
    config = load_config(args.paths[0].parent if args.paths else Path.cwd())
    report = lint_files(args.paths, config=config)
    _print_report(report, fmt=args.fmt, summary=args.summary)
    if args.exit_zero:
        return 0
    return 1 if report.total_errors > 0 else 0
