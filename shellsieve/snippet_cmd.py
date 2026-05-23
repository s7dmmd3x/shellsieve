"""CLI sub-command: ``shellsieve snippet`` — show contextual code snippets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.config import load_config
from shellsieve.scanner import scan_file
from shellsieve.snippet import extract_snippets
from shellsieve.snippet_formatter import TextSnippetFormatter


def build_snippet_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser(
        "snippet",
        help="Show source snippets with context around each finding.",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="Scripts to inspect.")
    p.add_argument(
        "--context",
        "-C",
        type=int,
        default=2,
        metavar="N",
        help="Lines of context above and below each match (default: 2).",
    )
    p.add_argument("--no-colour", action="store_true", help="Disable ANSI colour.")
    return p


def run_snippet(args: argparse.Namespace) -> int:
    config = load_config()
    formatter = TextSnippetFormatter(colour=not args.no_colour)
    found_any = False

    for raw in args.files:
        path = Path(raw)
        if not path.is_file():
            print(f"shellsieve snippet: {raw}: no such file", file=sys.stderr)
            return 2

        result = scan_file(path, config)
        snippets = extract_snippets(path, result.matches, context=args.context)

        if snippets:
            found_any = True
            print(formatter.render(path, snippets))

    return 1 if found_any else 0
