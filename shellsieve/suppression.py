"""Suppression support: honour inline `# shellsieve: disable=<ID>` comments."""

from __future__ import annotations

import re
from typing import Iterable

# Matches:  # shellsieve: disable=SS001,SS002
_DISABLE_RE = re.compile(
    r"#\s*shellsieve:\s*disable=([A-Z0-9,\s]+)",
    re.IGNORECASE,
)

# A sentinel that means "suppress everything on this line"
_WILDCARD = "*"


def parse_suppressed_ids(line: str) -> frozenset[str]:
    """Return the set of pattern IDs suppressed on *line*.

    Examples
    --------
    >>> parse_suppressed_ids('eval "$cmd"  # shellsieve: disable=SS003')
    frozenset({'SS003'})
    >>> parse_suppressed_ids('echo hi  # shellsieve: disable=SS001, SS002')
    frozenset({'SS001', 'SS002'})
    >>> parse_suppressed_ids('echo hi')
    frozenset()
    """
    match = _DISABLE_RE.search(line)
    if not match:
        return frozenset()
    raw = match.group(1)
    ids = {token.strip().upper() for token in raw.split(",") if token.strip()}
    return frozenset(ids)


def is_suppressed(pattern_id: str, suppressed: frozenset[str]) -> bool:
    """Return True when *pattern_id* is covered by the suppression set."""
    return _WILDCARD in suppressed or pattern_id.upper() in suppressed


def filter_suppressed(matches: Iterable, line: str) -> list:
    """Remove any Match objects whose pattern ID is suppressed on *line*.

    Parameters
    ----------
    matches:
        Iterable of ``scanner.Match`` instances.
    line:
        The raw source line (used to extract suppression annotations).

    Returns
    -------
    list
        Matches that were *not* suppressed.
    """
    suppressed = parse_suppressed_ids(line)
    if not suppressed:
        return list(matches)
    return [
        m for m in matches
        if not is_suppressed(m.pattern.id, suppressed)
    ]
