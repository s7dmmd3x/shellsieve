"""Baseline management for shellsieve.

Allows users to snapshot current findings so that only *new* issues are
reported on subsequent runs (similar to mypy's --baseline feature).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from shellsieve.scanner import Match

DEFAULT_BASELINE_FILE = ".shellsieve_baseline.json"


def _match_key(match: Match) -> dict:
    """Return a serialisable dict that uniquely identifies a match."""
    return {
        "file": str(match.file),
        "line_no": match.line_no,
        "pattern_id": match.pattern.id,
    }


def save_baseline(matches: Iterable[Match], path: Path | str = DEFAULT_BASELINE_FILE) -> None:
    """Persist *matches* to *path* as a JSON baseline file."""
    path = Path(path)
    entries = [_match_key(m) for m in matches]
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def load_baseline(path: Path | str = DEFAULT_BASELINE_FILE) -> list[dict]:
    """Load a previously saved baseline.  Returns an empty list if the file
    does not exist."""
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    return data


def filter_baseline(matches: Iterable[Match], baseline: list[dict]) -> list[Match]:
    """Return only those *matches* that are **not** present in *baseline*.

    A match is considered known if its (file, line_no, pattern_id) triple
    appears in the baseline entries.
    """
    known: set[tuple] = {
        (entry["file"], entry["line_no"], entry["pattern_id"])
        for entry in baseline
        if all(k in entry for k in ("file", "line_no", "pattern_id"))
    }
    return [
        m
        for m in matches
        if (str(m.file), m.line_no, m.pattern.id) not in known
    ]
