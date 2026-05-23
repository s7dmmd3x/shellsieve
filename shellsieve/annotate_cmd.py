"""CLI sub-command: annotate — print scripts with inline issue markers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from shellsieve.annotator import AnnotatedFile, AnnotatedLine, annotate_results
from shellsieve.config import load_config
from shellsieve.patterns import get_patterns_by_severity
from shellsieve.scanner import scan_file

_SEVERITY_MARKER = {"error": "[E]", "warning": "[W]", "info": "[I]"}
_COLOUR = {"error": "\033[31m", "warning": "\033[33m", "info": "\033[36m"}
_RESET = "\033[0m"


def build_annotate_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("annotate", help="Print scripts with inline issue markers")
    p.add_argument("files", nargs="+", metavar="FILE")
    p.add_argument("--only-issues", action="store_true", help="Print only lines with issues")
    p.add_argument("--no-colour", action="store_true", help="Disable ANSI colour")
    p.add_argument("--min-severity", choices=["error", "warning", "info"], default="info")
    return p


def _render_line(aline: AnnotatedLine, *, only_issues: bool, colour: bool) -> List[str]:
    if only_issues and not aline.has_issues:
        return []
    prefix = f"{aline.lineno:4d}  "
    out = [prefix + aline.text.rstrip()]
    for match in aline.matches:
        marker = _SEVERITY_MARKER.get(match.severity, "[?]")
        note = f"       {marker} {match.pattern.id}: {match.pattern.message}"
        if colour:
            c = _COLOUR.get(match.severity, "")
            note = c + note + _RESET
        out.append(note)
    return out


def _render_file(af: AnnotatedFile, *, only_issues: bool, colour: bool) -> None:
    print(f"==> {af.path} <==")
    for aline in af.lines:
        for rendered in _render_line(aline, only_issues=only_issues, colour=colour):
            print(rendered)


def run_annotate(args: argparse.Namespace) -> int:
    cfg = load_config()
    patterns = get_patterns_by_severity(args.min_severity) if args.min_severity != "info" else None

    results = []
    for raw in args.files:
        p = Path(raw)
        if not p.is_file():
            print(f"shellsieve annotate: {raw}: no such file", file=sys.stderr)
            return 2
        results.append(scan_file(str(p), patterns=patterns))

    annotated = annotate_results(results)
    colour = not args.no_colour and sys.stdout.isatty()
    for af in annotated:
        _render_file(af, only_issues=args.only_issues, colour=colour)

    any_issues = any(af.issue_lines for af in annotated)
    return 1 if any_issues else 0
