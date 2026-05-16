"""Command-line interface for shellsieve."""
from __future__ import annotations

import sys
import argparse
from pathlib import Path
from typing import List

from shellsieve.scanner import scan_file, ScanResult
from shellsieve.formatter import TextFormatter, JsonFormatter
from shellsieve.config import load_config
from shellsieve.baseline import load_baseline, filter_baseline, save_baseline
from shellsieve.suppression import filter_suppressed
from shellsieve.stats import compute_stats, format_stats


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shellsieve",
        description="Static analyzer for bash/zsh scripts.",
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="Scripts to analyze")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", dest="fmt"
    )
    parser.add_argument(
        "--exit-zero", action="store_true", help="Always exit with code 0"
    )
    parser.add_argument(
        "--update-baseline", action="store_true", help="Write current findings as baseline"
    )
    parser.add_argument(
        "--baseline", metavar="FILE", default=None, help="Path to baseline JSON file"
    )
    parser.add_argument(
        "--stats", action="store_true", help="Print aggregate scan statistics"
    )
    parser.add_argument(
        "--severity", choices=["info", "warning", "error"], default=None,
        help="Minimum severity level to report"
    )
    return parser


def run(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    config = load_config()
    formatter = JsonFormatter() if args.fmt == "json" else TextFormatter()

    baseline_path = Path(args.baseline) if args.baseline else None
    baseline = load_baseline(baseline_path) if baseline_path else []

    results: List[ScanResult] = []
    for file_arg in args.files:
        path = Path(file_arg)
        if not path.exists():
            print(f"shellsieve: file not found: {file_arg}", file=sys.stderr)
            continue
        result = scan_file(path, config=config)
        result = filter_suppressed(result)
        if baseline:
            result = filter_baseline(result, baseline)
        if args.severity:
            from shellsieve.patterns import Severity
            min_sev = Severity(args.severity)
            order = [Severity.INFO, Severity.WARNING, Severity.ERROR]
            allowed = order[order.index(min_sev):]
            from shellsieve.scanner import ScanResult as SR
            result = SR(
                path=result.path,
                matches=[m for m in result.matches if m.severity in allowed],
            )
        results.append(result)

    if args.update_baseline and baseline_path:
        all_matches = [m for r in results for m in r.matches]
        save_baseline(all_matches, baseline_path)

    print(formatter.format(results), end="")

    if args.stats:
        stats = compute_stats(results)
        print(format_stats(stats))

    if args.exit_zero:
        return 0
    return 1 if any(r.has_issues for r in results) else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
