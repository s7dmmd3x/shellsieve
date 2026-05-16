"""Command-line interface for shellsieve."""

from __future__ import annotations

import argparse
import sys
import pathlib

from shellsieve.config import load_config
from shellsieve.formatter import get_formatter
from shellsieve.scanner import scan_file
from shellsieve.suppression import filter_suppressed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shellsieve",
        description="Static analyzer for bash/zsh scripts.",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Shell script(s) to analyze.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="format",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit with code 0, even when issues are found.",
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Minimum severity level to report.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    config = load_config()
    formatter = get_formatter(args.format)
    found_issues = False

    for file_arg in args.files:
        path = pathlib.Path(file_arg)
        if not path.exists():
            print(f"shellsieve: {file_arg}: file not found", file=sys.stderr)
            continue

        result = scan_file(path)
        result = filter_suppressed(result)

        if args.severity:
            from shellsieve.patterns import Severity
            min_sev = Severity[args.severity]
            result.matches = [
                m for m in result.matches
                if Severity[m.severity] >= min_sev
            ]

        print(formatter.format(result), end="")

        if result.has_issues():
            found_issues = True

    if found_issues and not args.exit_zero:
        return 1
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
