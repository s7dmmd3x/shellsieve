"""Formatters for trend reports (text and JSON)."""
from __future__ import annotations

import datetime
import json
from typing import List

from shellsieve.trend import TrendReport, TrendEntry


class TrendFormatter:
    """Base class for trend formatters."""

    def render(self, report: TrendReport, last: int = 10) -> str:
        raise NotImplementedError


class TextTrendFormatter(TrendFormatter):
    def __init__(self, no_colour: bool = False):
        self._no_colour = no_colour

    def _fmt_ts(self, ts: float) -> str:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def _sign(self, n: int) -> str:
        return f"+{n}" if n > 0 else str(n)

    def render(self, report: TrendReport, last: int = 10) -> str:
        entries: List[TrendEntry] = report.entries[-last:]
        if not entries:
            return "No trend data recorded yet."
        lines = []
        header = f"{'Timestamp':<22} {'Total':>6} {'Errors':>7} {'Warnings':>9}"
        lines.append(header)
        lines.append("-" * len(header))
        for e in entries:
            lines.append(
                f"{self._fmt_ts(e.timestamp):<22} {e.total_issues:>6} "
                f"{e.error_count:>7} {e.warning_count:>9}"
            )
        delta = report.delta()
        if delta is not None:
            lines.append(
                f"\nDelta (last 2 runs): total={self._sign(delta['total_issues'])}  "
                f"errors={self._sign(delta['error_count'])}  "
                f"warnings={self._sign(delta['warning_count'])}"
            )
        return "\n".join(lines)


class JsonTrendFormatter(TrendFormatter):
    def render(self, report: TrendReport, last: int = 10) -> str:
        entries = report.entries[-last:]
        payload = {
            "entries": [e.as_dict() for e in entries],
            "delta": report.delta(),
        }
        return json.dumps(payload, indent=2)


def get_trend_formatter(fmt: str = "text", no_colour: bool = False) -> TrendFormatter:
    if fmt == "json":
        return JsonTrendFormatter()
    return TextTrendFormatter(no_colour=no_colour)
