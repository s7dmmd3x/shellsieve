"""CLI sub-command: tag — show matches grouped by inferred category."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.patterns import get_patterns_by_tag
from shellsieve.scanner import scan_file
from shellsieve.tagger import group_by_category, tag_matches


def build_tag_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = subparsers.add_parser(
        "tag",
        help="Display matches grouped by inferred risk category.",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="Scripts to analyse.")
    p.add_argument(
        "--category",
        metavar="NAME",
        default=None,
        help="Filter output to a specific category name (case-insensitive).",
    )
    p.add_argument("--no-colour", action="store_true", default=False)
    return p


def run_tag(args: argparse.Namespace) -> int:
    from shellsieve.patterns import PATTERNS  # local import to avoid circularity

    all_matches = []
    for path_str in args.files:
        p = Path(path_str)
        if not p.is_file():
            print(f"shellsieve tag: {path_str}: no such file", file=sys.stderr)
            return 2
        result = scan_file(p, PATTERNS)
        all_matches.extend(result.matches)

    tagged = tag_matches(all_matches)
    groups = group_by_category(tagged)

    filter_cat = args.category.lower() if args.category else None

    if not groups:
        print("No issues found.")
        return 0

    for category, items in sorted(groups.items()):
        if filter_cat and filter_cat not in category.lower():
            continue
        print(f"\n[{category}] ({len(items)} match{'es' if len(items) != 1 else ''})")  # noqa: E501
        for tm in items:
            m = tm.match
            print(f"  {m.path}:{m.line_number}  [{m.pattern.id}]  {m.line.rstrip()}")

    return 0
