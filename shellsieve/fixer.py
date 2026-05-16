"""Suggests or applies automatic fixes for flagged patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from shellsieve.scanner import Match


@dataclass
class Fix:
    """A suggested fix for a matched pattern."""

    match: Match
    original_line: str
    fixed_line: str
    description: str

    def __str__(self) -> str:
        return (
            f"  - {self.description}\n"
            f"    Before: {self.original_line.rstrip()}\n"
            f"    After:  {self.fixed_line.rstrip()}"
        )


# Registry: pattern_id -> (description, transform)
_FIXERS: dict[str, tuple[str, re.Pattern[str], str]] = {
    "SC001": (
        "Quote variable to prevent word splitting",
        re.compile(r"(?<!\$)\$(\w+)"),
        r'"$\1"',
    ),
    "SC004": (
        "Use [[ ]] instead of [ ] for safer conditionals",
        re.compile(r"\[ (.*?) \]"),
        r"[[ \1 ]]",
    ),
}


def suggest_fix(match: Match, line: str) -> Optional[Fix]:
    """Return a Fix for *match* on *line*, or None if no fixer is registered."""
    entry = _FIXERS.get(match.pattern.id)
    if entry is None:
        return None
    description, pattern, replacement = entry
    fixed_line, count = pattern.subn(replacement, line)
    if count == 0:
        return None
    return Fix(
        match=match,
        original_line=line,
        fixed_line=fixed_line,
        description=description,
    )


def suggest_fixes_for_lines(
    matches_by_line: dict[int, list[Match]], lines: list[str]
) -> list[Fix]:
    """Return all fixes for a set of matches indexed by 1-based line number."""
    fixes: list[Fix] = []
    for lineno, ms in matches_by_line.items():
        line = lines[lineno - 1] if 1 <= lineno <= len(lines) else ""
        for m in ms:
            fix = suggest_fix(m, line)
            if fix is not None:
                fixes.append(fix)
    return fixes
