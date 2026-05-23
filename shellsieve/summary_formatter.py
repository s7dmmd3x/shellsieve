"""Pluggable formatters for the scan summary output."""
from __future__ import annotations

import csv
import io
import json
from typing import Protocol

from shellsieve.patterns import Severity
from shellsieve.summarizer import ScanSummary, format_summary


class SummaryFormatter(Protocol):
    """Interface for summary formatters."""

    def render(self, summary: ScanSummary) -> str:
        ...


class TextSummaryFormatter:
    """Plain-text (ANSI-optionally-coloured) summary."""

    def __init__(self, *, colour: bool = True) -> None:
        self._colour = colour

    def render(self, summary: ScanSummary) -> str:
        return format_summary(summary, colour=self._colour)


class JsonSummaryFormatter:
    """JSON summary formatter."""

    def render(self, summary: ScanSummary) -> str:
        return json.dumps(summary.as_dict(), indent=2)


class CsvSummaryFormatter:
    """CSV summary formatter — one row per severity level."""

    def render(self, summary: ScanSummary) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["severity", "count"])
        for sev in Severity:
            grp = summary.groups.get(sev.name)
            writer.writerow([sev.name, grp.count if grp else 0])
        return buf.getvalue().rstrip()


_REGISTRY: dict[str, type] = {
    "text": TextSummaryFormatter,
    "json": JsonSummaryFormatter,
    "csv": CsvSummaryFormatter,
}


def get_summary_formatter(fmt: str, **kwargs) -> SummaryFormatter:
    """Return a formatter instance for *fmt* name.

    Raises :class:`ValueError` for unknown format names.
    """
    try:
        cls = _REGISTRY[fmt.lower()]
    except KeyError:
        valid = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"Unknown summary format {fmt!r}. Valid options: {valid}")
    return cls(**kwargs)
