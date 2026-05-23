"""Snippet extractor: pulls context lines around each match for richer output."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from shellsieve.scanner import Match


@dataclass
class Snippet:
    """A block of source lines centred on a match."""

    match: Match
    lines: List[str]          # raw lines (no trailing newline)
    start_lineno: int         # 1-based line number of lines[0]
    highlight_index: int      # index within *lines* that contains the match

    @property
    def highlight_lineno(self) -> int:
        return self.start_lineno + self.highlight_index


def extract_snippet(
    path: Path,
    match: Match,
    context: int = 2,
) -> Optional[Snippet]:
    """Return a Snippet for *match* with *context* lines above and below.

    Returns ``None`` when the file cannot be read or the line number is out of
    range.
    """
    try:
        all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    # match.lineno is 1-based
    idx = match.lineno - 1
    if idx < 0 or idx >= len(all_lines):
        return None

    first = max(0, idx - context)
    last = min(len(all_lines) - 1, idx + context)

    return Snippet(
        match=match,
        lines=all_lines[first : last + 1],
        start_lineno=first + 1,
        highlight_index=idx - first,
    )


def extract_snippets(
    path: Path,
    matches: List[Match],
    context: int = 2,
) -> List[Snippet]:
    """Extract snippets for every match in *matches*."""
    return [
        s
        for m in matches
        for s in (extract_snippet(path, m, context),)
        if s is not None
    ]
