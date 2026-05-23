"""CLI sub-command: shellsieve explain — show detailed explanations for findings."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.config import load_config
from shellsieve.explainer import Explanation, explain_matches
from shellsieve.scanner import scan_file


def build_explain_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("explain", help="Show detailed explanations for each finding.")
    p.add_argument("paths", nargs="+", metavar="FILE", help="Shell scripts to analyse.")
    p.add_argument("--no-colour", action="store_true", default=False)
    p.add_argument("--json", action="store_true", default=False, help="Output as JSON.")
    return p


def _colour(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


_SEVERITY_COLOUR = {"ERROR": "31", "WARNING": "33", "INFO": "36"}


def _render_explanation(exp: Explanation, colour: bool) -> str:
    sev_code = _SEVERITY_COLOUR.get(exp.severity, "0")
    header = _colour(f"[{exp.pattern_id}] {exp.pattern_description}", sev_code, colour)
    location = _colour(f"  {exp.file_path}:{exp.lineno}", "2", colour)
    matched = f"  > {exp.matched_text}"
    prose = f"  {exp.prose}"
    parts = [header, location, matched, prose]
    if exp.reference_url:
        parts.append(f"  ref: {exp.reference_url}")
    return "\n".join(parts)


def run_explain(args: argparse.Namespace) -> int:
    import json

    config = load_config()
    colour = not args.no_colour and sys.stdout.isatty()
    all_explanations: list[dict] = []
    found_any = False
    exit_code = 0

    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.is_file():
            print(f"shellsieve explain: {raw_path}: file not found", file=sys.stderr)
            return 2

        result = scan_file(str(path), config=config)
        if result.matches:
            found_any = True
            explanations = explain_matches(result.matches, file_path=str(path))
            if args.json:
                all_explanations.extend(e.as_dict() for e in explanations)
            else:
                for exp in explanations:
                    print(_render_explanation(exp, colour))
                    print()

    if args.json:
        print(json.dumps(all_explanations, indent=2))

    if found_any:
        exit_code = 1
    return exit_code
