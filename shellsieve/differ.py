"""Diff-aware scanning: compare scan results between two revisions or runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from shellsieve.scanner import Match


def _match_key(m: Match) -> Tuple[str, int, str]:
    """Stable identity key for a match (path, line, pattern id)."""
    return (m.path, m.line_number, m.pattern.id)


@dataclass
class DiffResult:
    """Holds the delta between a baseline run and a current run."""

    added: List[Match] = field(default_factory=list)
    removed: List[Match] = field(default_factory=list)
    unchanged: List[Match] = field(default_factory=list)

    @property
    def has_new_issues(self) -> bool:
        return len(self.added) > 0

    def summary(self) -> str:
        return (
            f"+{len(self.added)} new  "
            f"-{len(self.removed)} fixed  "
            f"={len(self.unchanged)} unchanged"
        )


def diff_matches(before: List[Match], after: List[Match]) -> DiffResult:
    """Return a DiffResult describing what changed between two match lists."""
    before_keys = {_match_key(m): m for m in before}
    after_keys = {_match_key(m): m for m in after}

    added = [m for k, m in after_keys.items() if k not in before_keys]
    removed = [m for k, m in before_keys.items() if k not in after_keys]
    unchanged = [m for k, m in after_keys.items() if k in before_keys]

    return DiffResult(added=added, removed=removed, unchanged=unchanged)


def format_diff(diff: DiffResult, *, colour: bool = True) -> str:
    """Render a human-readable diff summary."""
    lines: List[str] = []

    green = "\033[32m" if colour else ""
    red = "\033[31m" if colour else ""
    reset = "\033[0m" if colour else ""

    for m in diff.added:
        lines.append(f"{red}+ {m.path}:{m.line_number} [{m.pattern.id}] {m.pattern.description}{reset}")

    for m in diff.removed:
        lines.append(f"{green}- {m.path}:{m.line_number} [{m.pattern.id}] {m.pattern.description}{reset}")

    if not lines:
        lines.append(f"{green}No new issues introduced.{reset}")

    lines.append("")
    lines.append(diff.summary())
    return "\n".join(lines)
