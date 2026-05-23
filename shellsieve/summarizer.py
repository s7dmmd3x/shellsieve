"""Summarizer: produce a human-readable scan summary grouped by severity."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from shellsieve.patterns import Severity
from shellsieve.scanner import Match, ScanResult


@dataclass
class SeverityGroup:
    severity: Severity
    matches: List[Match] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.matches)


@dataclass
class ScanSummary:
    groups: Dict[str, SeverityGroup] = field(default_factory=dict)
    total_files: int = 0
    total_matches: int = 0

    def as_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "total_matches": self.total_matches,
            "by_severity": {
                name: {"count": grp.count}
                for name, grp in self.groups.items()
            },
        }


def summarize(results: Sequence[ScanResult]) -> ScanSummary:
    """Aggregate *results* into a :class:`ScanSummary`."""
    groups: Dict[str, SeverityGroup] = {}
    total_matches = 0

    for result in results:
        for match in result.matches:
            sev = match.severity
            key = sev.name
            if key not in groups:
                groups[key] = SeverityGroup(severity=sev)
            groups[key].matches.append(match)
            total_matches += 1

    # Ensure all severity levels are present even with zero matches
    for sev in Severity:
        if sev.name not in groups:
            groups[sev.name] = SeverityGroup(severity=sev)

    return ScanSummary(
        groups=groups,
        total_files=len(results),
        total_matches=total_matches,
    )


def format_summary(summary: ScanSummary, *, colour: bool = True) -> str:
    """Return a formatted multi-line string for *summary*."""
    _RESET = "\033[0m" if colour else ""
    _BOLD = "\033[1m" if colour else ""
    _COLOURS = {
        Severity.ERROR: "\033[31m" if colour else "",
        Severity.WARNING: "\033[33m" if colour else "",
        Severity.INFO: "\033[36m" if colour else "",
    }

    lines = [f"{_BOLD}Scan summary{_RESET}"]
    lines.append(f"  Files scanned : {summary.total_files}")
    lines.append(f"  Total matches : {summary.total_matches}")
    for sev in Severity:
        grp = summary.groups.get(sev.name)
        count = grp.count if grp else 0
        c = _COLOURS.get(sev, "")
        lines.append(f"  {c}{sev.name:<8}{_RESET}: {count}")
    return "\n".join(lines)
