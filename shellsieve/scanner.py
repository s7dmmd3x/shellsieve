"""Core scanner module: reads shell scripts and matches unsafe patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from shellsieve.patterns import Pattern, Severity, PATTERNS


@dataclass
class Match:
    """Represents a single pattern match found in a script."""

    pattern: Pattern
    line_number: int
    line_content: str
    column_start: int
    column_end: int

    @property
    def severity(self) -> Severity:
        return self.pattern.severity

    def __str__(self) -> str:
        return (
            f"[{self.severity.name}] Line {self.line_number}: "
            f"{self.pattern.message} (rule: {self.pattern.id})"
        )


@dataclass
class ScanResult:
    """Aggregated results for a single file scan."""

    filepath: Path
    matches: List[Match] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.matches)

    def matches_by_severity(self, severity: Severity) -> List[Match]:
        return [m for m in self.matches if m.severity == severity]


def scan_line(line: str, line_number: int, patterns: List[Pattern]) -> List[Match]:
    """Scan a single line against all patterns and return any matches."""
    found: List[Match] = []
    for pattern in patterns:
        for m in pattern.regex.finditer(line):
            found.append(
                Match(
                    pattern=pattern,
                    line_number=line_number,
                    line_content=line.rstrip("\n"),
                    column_start=m.start(),
                    column_end=m.end(),
                )
            )
    return found


def scan_file(filepath: Path, patterns: Optional[List[Pattern]] = None) -> ScanResult:
    """Scan a shell script file and return a ScanResult."""
    if patterns is None:
        patterns = PATTERNS

    result = ScanResult(filepath=filepath)

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result

    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        result.matches.extend(scan_line(line, lineno, patterns))

    return result
