"""Whole-file and directory ignore logic for shellsieve."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterable, List

# Default glob patterns that are always ignored
_DEFAULT_IGNORE_PATTERNS: List[str] = [
    ".git/*",
    "node_modules/*",
    "*.bak",
    "*.swp",
]


def _normalise(path: str | Path) -> str:
    """Return a forward-slash, relative-style string for pattern matching."""
    return str(path).replace(os.sep, "/")


def matches_ignore_pattern(path: str | Path, patterns: Iterable[str]) -> bool:
    """Return True if *path* matches any glob in *patterns*."""
    normalised = _normalise(path)
    for pattern in patterns:
        if fnmatch.fnmatch(normalised, pattern):
            return True
        # Also match against the basename alone so "*.bak" works for any depth
        if fnmatch.fnmatch(os.path.basename(normalised), pattern):
            return True
    return False


def build_ignore_patterns(
    extra_patterns: Iterable[str] | None = None,
) -> List[str]:
    """Merge default patterns with any user-supplied extras."""
    patterns = list(_DEFAULT_IGNORE_PATTERNS)
    if extra_patterns:
        patterns.extend(extra_patterns)
    return patterns


def filter_paths(
    paths: Iterable[str | Path],
    patterns: Iterable[str] | None = None,
) -> List[Path]:
    """Return only those *paths* that are NOT matched by any ignore pattern."""
    effective = build_ignore_patterns(patterns)
    return [
        Path(p)
        for p in paths
        if not matches_ignore_pattern(p, effective)
    ]
