"""Command-line interface for shellsieve."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import argparse

from shellsieve.patterns import Severity, PATTERNS
from shellsieve.reporter import print_results
from shellsieve.scanner import scan_file, ScanResult


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shellsieve",
        description="Static analyzer for bash/zsh scripts.",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Shell script file(s) to analyze.",
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.name.lower() for s in Severity],
        default="low",
        help="Minimum severity level to report (default: low).",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour output.",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit with code 0, even when issues are found.",
    )
    return parser


def run(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    min_sev = Severity[args.min_severity.upper()]
    active_patterns = [p for p in PATTERNS if p.severity.value >= min_sev.value]

    results: List[ScanResult] = []
    for raw_path in args.files:
        path = Path(raw_path)
        if not path.exists():
            print(f"shellsieve: {raw_path}: file not found", file=sys.stderr)
            continue
        results.append(scan_file(path, patterns=active_patterns))

    print_results(results, use_colour=not args.no_colour)

    if args.exit_zero:
        return 0
    return 1 if any(r.has_issues for r in results) else 0


def main() -> None:  # pragma: no cover
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
