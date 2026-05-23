"""CLI sub-command: trend — record and display scan trend history."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsieve.scanner import scan_files
from shellsieve.stats import compute_stats
from shellsieve.trend import load_trend, save_trend, record_entry, make_entry

_DEFAULT_TREND_FILE = ".shellsieve_trend.json"


def build_trend_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subparsers.add_parser("trend", help="Record scan results and show historical trend")
    p.add_argument("paths", nargs="+", help="Scripts or directories to scan")
    p.add_argument(
        "--trend-file",
        default=_DEFAULT_TREND_FILE,
        help="Path to trend history file (default: .shellsieve_trend.json)",
    )
    p.add_argument("--no-record", action="store_true", help="Show trend without recording a new entry")
    p.add_argument("--last", type=int, default=10, metavar="N", help="Show last N entries")
    return p


def _print_trend(report, last: int, no_colour: bool = False) -> None:
    entries = report.entries[-last:]
    if not entries:
        print("No trend data recorded yet.")
        return
    print(f"{'Timestamp':<22} {'Total':>6} {'Errors':>7} {'Warnings':>9}")
    print("-" * 50)
    for e in entries:
        import datetime
        ts = datetime.datetime.fromtimestamp(e.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts:<22} {e.total_issues:>6} {e.error_count:>7} {e.warning_count:>9}")
    delta = report.delta()
    if delta is not None:
        sign = lambda n: f"+{n}" if n > 0 else str(n)
        print(f"\nDelta (last 2 runs): total={sign(delta['total_issues'])}  "
              f"errors={sign(delta['error_count'])}  warnings={sign(delta['warning_count'])}")


def run_trend(args: argparse.Namespace) -> int:
    target_paths = [Path(p) for p in args.paths]
    missing = [p for p in target_paths if not p.exists()]
    if missing:
        for m in missing:
            print(f"shellsieve: {m}: no such file or directory", file=sys.stderr)
        return 2

    results = scan_files(target_paths)
    trend_path = Path(args.trend_file)
    report = load_trend(trend_path)

    if not args.no_record:
        stats = compute_stats(results)
        entry = make_entry(stats.as_dict())
        report = record_entry(report, entry)
        save_trend(report, trend_path)

    _print_trend(report, last=args.last)
    return 0
