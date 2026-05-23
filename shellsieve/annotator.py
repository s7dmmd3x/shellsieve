"""Annotate shell script lines with match metadata for rich output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from shellsieve.scanner import Match, ScanResult


@dataclass
class AnnotatedLine:
    """A single script line paired with any matches found on it."""

    lineno: int
    text: str
    matches: List[Match] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.matches)

    @property
    def highest_severity(self) -> Optional[str]:
        if not self.matches:
            return None
        order = {"error": 0, "warning": 1, "info": 2}
        return min(
            (m.severity for m in self.matches),
            key=lambda s: order.get(s, 99),
        )


@dataclass
class AnnotatedFile:
    """All annotated lines for a single file."""

    path: str
    lines: List[AnnotatedLine] = field(default_factory=list)

    @property
    def issue_lines(self) -> List[AnnotatedLine]:
        return [ln for ln in self.lines if ln.has_issues]


def annotate_result(result: ScanResult) -> AnnotatedFile:
    """Build an :class:`AnnotatedFile` from a :class:`ScanResult`.

    Lines without any matches are included so callers can render full
    context around flagged lines when needed.
    """
    # Index matches by line number for O(1) lookup.
    by_line: dict[int, List[Match]] = {}
    for match in result.matches:
        by_line.setdefault(match.lineno, []).append(match)

    lines: List[AnnotatedLine] = []
    for lineno, text in enumerate(result.lines, start=1):
        lines.append(
            AnnotatedLine(
                lineno=lineno,
                text=text,
                matches=by_line.get(lineno, []),
            )
        )

    return AnnotatedFile(path=result.path, lines=lines)


def annotate_results(results: List[ScanResult]) -> List[AnnotatedFile]:
    """Annotate a list of scan results."""
    return [annotate_result(r) for r in results]
