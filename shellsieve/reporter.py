"""Reporting utilities: format ScanResult objects for terminal output."""

from __future__ import annotations

from typing import List

from shellsieve.patterns import Severity
from shellsieve.scanner import Match, ScanResult

# ANSI colour codes
_RESET = "\033[0m"
_COLOURS = {
    Severity.LOW: "\033[36m",      # cyan
    Severity.MEDIUM: "\033[33m",   # yellow
    Severity.HIGH: "\033[31m",     # red
    Severity.CRITICAL: "\033[35m", # magenta
}


def _colour(text: str, severity: Severity, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{_COLOURS.get(severity, '')}{text}{_RESET}"


def format_match(match: Match, use_colour: bool = True) -> str:
    """Return a single-line human-readable description of a match."""
    tag = _colour(f"[{match.severity.name:<8}]", match.severity, use_colour)
    location = f"{match.line_number}:{match.column_start}"
    return (
        f"  {tag} line {location:>8}  {match.pattern.message}\n"
        f"             {match.line_content.strip()}"
    )


def format_result(result: ScanResult, use_colour: bool = True) -> str:
    """Return a full formatted report for one file."""
    lines: List[str] = []
    header = f"==> {result.filepath}"
    lines.append(header)

    if result.errors:
        for err in result.errors:
            lines.append(f"  ERROR: {err}")
        return "\n".join(lines)

    if not result.has_issues:
        lines.append("  No issues found.")
        return "\n".join(lines)

    for match in result.matches:
        lines.append(format_match(match, use_colour=use_colour))

    total = len(result.matches)
    counts = {
        sev: len(result.matches_by_severity(sev)) for sev in Severity
    }
    summary_parts = [
        f"{counts[sev]} {sev.name.lower()}"
        for sev in Severity
        if counts[sev]
    ]
    lines.append(f"  Summary: {total} issue(s) — " + ", ".join(summary_parts))
    return "\n".join(lines)


def print_results(results: List[ScanResult], use_colour: bool = True) -> None:
    """Print formatted results for multiple files to stdout."""
    for result in results:
        print(format_result(result, use_colour=use_colour))
        print()
