"""Aggregates scan statistics from ScanResult objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from collections import Counter
from typing import Iterable

from shellsieve.scanner import ScanResult
from shellsieve.patterns import Severity


@dataclass
class ScanStats:
    total_files: int = 0
    files_with_issues: int = 0
    total_matches: int = 0
    by_severity: Counter = field(default_factory=Counter)
    by_pattern_id: Counter = field(default_factory=Counter)

    @property
    def clean_files(self) -> int:
        return self.total_files - self.files_with_issues

    def as_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "files_with_issues": self.files_with_issues,
            "clean_files": self.clean_files,
            "total_matches": self.total_matches,
            "by_severity": dict(self.by_severity),
            "by_pattern_id": dict(self.by_pattern_id),
        }


def compute_stats(results: Iterable[ScanResult]) -> ScanStats:
    """Compute aggregate statistics across multiple ScanResult objects."""
    stats = ScanStats()
    for result in results:
        stats.total_files += 1
        if result.has_issues:
            stats.files_with_issues += 1
        for match in result.matches:
            stats.total_matches += 1
            stats.by_severity[match.severity.value] += 1
            stats.by_pattern_id[match.pattern.id] += 1
    return stats


def format_stats(stats: ScanStats) -> str:
    """Return a human-readable summary string for the given stats."""
    lines = [
        "--- Scan Summary ---",
        f"Files scanned : {stats.total_files}",
        f"Files clean   : {stats.clean_files}",
        f"Files with issues: {stats.files_with_issues}",
        f"Total matches : {stats.total_matches}",
    ]
    if stats.by_severity:
        lines.append("By severity:")
        for sev in (s.value for s in Severity):
            count = stats.by_severity.get(sev, 0)
            if count:
                lines.append(f"  {sev:<10}: {count}")
    if stats.by_pattern_id:
        lines.append("By pattern ID:")
        for pid, count in stats.by_pattern_id.most_common():
            lines.append(f"  {pid:<12}: {count}")
    return "\n".join(lines)
