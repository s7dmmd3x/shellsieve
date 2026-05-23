"""CLI sub-command: ``shellsieve summary`` — print a grouped severity summary."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from shellsieve.patterns import get_patterns_by_severity, Severity
from shellsieve.scanner import scan_file
from shellsieve.summarizer import summarize, format_summary


def build_summary_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # noqa: SLF001
    p = subparsers.add_parser(
        "summary",
        help="Print a grouped severity summary for one or more scripts.",
    )
    p.add_argument("paths", nargs="+", metavar="FILE", help="Shell scripts to analyse.")
    p.add_argument(
        "--no-colour",
        action="store_true",
        default=False,
        help="Disable ANSI colour output.",
    )
    p.add_argument(
        "--min-severity",
        choices=[s.name for s in Severity],
        default=None,
        help="Only include matches at or above this severity.",
    )
    return p


def run_summary(args: argparse.Namespace) -> int:
    patterns = get_patterns_by_severity(Severity[args.min_severity]) if args.min_severity else None

    results = []
    for raw in args.paths:
        path = Path(raw)
        if not path.is_file():
            print(f"shellsieve: {path}: no such file", file=sys.stderr)
            continue
        result = scan_file(path, patterns=patterns)
        results.append(result)

    if not results:
        print("shellsieve: no files scanned.", file=sys.stderr)
        return 2

    summary = summarize(results)
    print(format_summary(summary, colour=not args.no_colour))
    return 0 if summary.total_matches == 0 else 1
