"""CLI sub-command: shellsieve diff — compare two baseline JSON files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.baseline import load_baseline
from shellsieve.differ import diff_matches, format_diff


def build_diff_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = subparsers.add_parser(
        "diff",
        help="Compare two baseline files and report new / fixed issues.",
    )
    p.add_argument("before", metavar="BEFORE", help="Path to the older baseline JSON file.")
    p.add_argument("after", metavar="AFTER", help="Path to the newer baseline JSON file.")
    p.add_argument(
        "--no-colour",
        action="store_true",
        default=False,
        help="Disable ANSI colour output.",
    )
    p.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit 0, even when new issues are found.",
    )
    return p


def run_diff(args: argparse.Namespace) -> int:
    before_path = Path(args.before)
    after_path = Path(args.after)

    for p in (before_path, after_path):
        if not p.exists():
            print(f"shellsieve diff: file not found: {p}", file=sys.stderr)
            return 2

    before_matches = load_baseline(before_path)
    after_matches = load_baseline(after_path)

    result = diff_matches(before_matches, after_matches)
    print(format_diff(result, colour=not args.no_colour))

    if args.exit_zero:
        return 0
    return 1 if result.has_new_issues else 0
