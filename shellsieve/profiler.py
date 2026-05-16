"""Profiler module: tracks and reports per-pattern match frequency across scans."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from shellsieve.scanner import Match


@dataclass
class PatternProfile:
    """Aggregated hit statistics for a single pattern."""

    pattern_id: str
    description: str
    hit_count: int
    files_affected: int

    def as_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "description": self.description,
            "hit_count": self.hit_count,
            "files_affected": self.files_affected,
        }


@dataclass
class ScanProfile:
    """Collected profiling data for an entire scan run."""

    profiles: list[PatternProfile] = field(default_factory=list)

    def top(self, n: int = 5) -> list[PatternProfile]:
        """Return the *n* most frequently triggered patterns."""
        return sorted(self.profiles, key=lambda p: p.hit_count, reverse=True)[:n]

    def as_dict(self) -> dict:
        return {"profiles": [p.as_dict() for p in self.profiles]}


def build_profile(matches_by_file: dict[str, list[Match]]) -> ScanProfile:
    """Build a :class:`ScanProfile` from a mapping of filepath -> matches.

    Args:
        matches_by_file: Keys are file paths; values are the :class:`Match`
            objects found in that file.

    Returns:
        A :class:`ScanProfile` with one :class:`PatternProfile` per distinct
        pattern ID encountered across all files.
    """
    hit_counts: Counter[str] = Counter()
    files_per_pattern: dict[str, set[str]] = {}
    descriptions: dict[str, str] = {}

    for filepath, matches in matches_by_file.items():
        for match in matches:
            pid = match.pattern.id
            hit_counts[pid] += 1
            files_per_pattern.setdefault(pid, set()).add(filepath)
            descriptions.setdefault(pid, match.pattern.description)

    profiles = [
        PatternProfile(
            pattern_id=pid,
            description=descriptions[pid],
            hit_count=count,
            files_affected=len(files_per_pattern[pid]),
        )
        for pid, count in hit_counts.items()
    ]

    return ScanProfile(profiles=profiles)


def format_profile(profile: ScanProfile, top_n: int = 5) -> str:
    """Render a human-readable summary of the top-N hottest patterns."""
    lines: list[str] = ["Pattern hit profile (top {:d}):".format(top_n)]
    for rank, p in enumerate(profile.top(top_n), start=1):
        lines.append(
            "  {:d}. [{:s}] {:s} — {:d} hit(s) in {:d} file(s)".format(
                rank, p.pattern_id, p.description, p.hit_count, p.files_affected
            )
        )
    if not profile.profiles:
        lines.append("  (no matches recorded)")
    return "\n".join(lines)
