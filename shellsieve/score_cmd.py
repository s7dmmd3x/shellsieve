"""CLI sub-command: shellsieve score — show risk scores for scanned files."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shellsieve.scanner import scan_file
from shellsieve.scorer import build_score_report, ScoreReport


def build_score_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = subparsers.add_parser(
        "score",
        help="Print numeric risk scores for each file.",
    )
    p.add_argument("paths", nargs="+", metavar="FILE", help="Scripts to score.")
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--fail-above",
        type=int,
        default=None,
        metavar="N",
        help="Exit with code 1 if total score exceeds N.",
    )
    return p


def _print_text(report: ScoreReport, out=sys.stdout) -> None:
    for fs in report.file_scores:
        out.write(
            f"{fs.path}: score={fs.score} risk={fs.risk_label} matches={fs.match_count}\n"
        )
    out.write(f"Total score: {report.total_score}\n")
    best = report.highest_risk_file
    if best and best.score > 0:
        out.write(f"Highest risk: {best.path} ({best.risk_label})\n")


def run_score(args: argparse.Namespace) -> int:
    results = []
    for raw_path in args.paths:
        p = Path(raw_path)
        if not p.is_file():
            sys.stderr.write(f"shellsieve score: {raw_path}: file not found\n")
            return 2
        results.append(scan_file(str(p)))

    report = build_score_report(results)

    if args.format == "json":
        sys.stdout.write(json.dumps(report.as_dict(), indent=2) + "\n")
    else:
        _print_text(report)

    if args.fail_above is not None and report.total_score > args.fail_above:
        return 1
    return 0
