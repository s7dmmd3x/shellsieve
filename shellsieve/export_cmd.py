"""CLI sub-command: shellsieve export — scan files and emit machine-readable output."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.exporter import ExportFormat, export
from shellsieve.scanner import ScanResult, scan_file

_FORMATS: list[ExportFormat] = ["json", "csv", "sarif"]


def build_export_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    """Attach the *export* sub-command to an existing subparsers group."""
    parser: argparse.ArgumentParser = subparsers.add_parser(
        "export",
        help="Scan scripts and write results in a machine-readable format.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="Shell script file(s) to scan.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=_FORMATS,
        default="json",
        dest="fmt",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=None,
        help="Write output to FILE instead of stdout.",
    )
    parser.set_defaults(func=run_export)
    return parser


def run_export(args: argparse.Namespace) -> int:
    """Execute the export sub-command; returns an exit code."""
    results: list[ScanResult] = []
    missing: list[str] = []

    for raw in args.paths:
        path = Path(raw)
        if not path.is_file():
            print(f"shellsieve export: {raw}: no such file", file=sys.stderr)
            missing.append(raw)
            continue
        results.append(scan_file(str(path)))

    if missing:
        return 2

    output = export(results, args.fmt)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    any_issues = any(r.has_issues() for r in results)
    return 1 if any_issues else 0
