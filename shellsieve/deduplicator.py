"""Deduplicator – collapse duplicate matches across a scan result.

Two matches are considered duplicates when they share the same
(file, line_number, pattern_id) triple.  When duplicates exist the
first occurrence is kept and the rest are dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Tuple

from shellsieve.scanner import Match, ScanResult


# ---------------------------------------------------------------------------
# Key type
# ---------------------------------------------------------------------------

_DedupKey = Tuple[str, int, str]  # (file_path, line_number, pattern_id)


def _match_key(match: Match) -> _DedupKey:
    return (match.file_path, match.line_number, match.pattern.id)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class DeduplicationReport:
    """Summary of what was removed during deduplication."""

    original_count: int
    deduplicated_count: int
    removed_keys: List[_DedupKey] = field(default_factory=list)

    @property
    def removed_count(self) -> int:
        return self.original_count - self.deduplicated_count

    def as_dict(self) -> Dict:
        return {
            "original_count": self.original_count,
            "deduplicated_count": self.deduplicated_count,
            "removed_count": self.removed_count,
        }


def deduplicate_matches(matches: List[Match]) -> Tuple[List[Match], DeduplicationReport]:
    """Return a de-duplicated list of matches and a report."""
    seen: Dict[_DedupKey, bool] = {}
    kept: List[Match] = []
    removed_keys: List[_DedupKey] = []

    for match in matches:
        key = _match_key(match)
        if key in seen:
            removed_keys.append(key)
        else:
            seen[key] = True
            kept.append(match)

    report = DeduplicationReport(
        original_count=len(matches),
        deduplicated_count=len(kept),
        removed_keys=removed_keys,
    )
    return kept, report


def deduplicate_results(
    results: List[ScanResult],
) -> Tuple[List[ScanResult], DeduplicationReport]:
    """Deduplicate matches across an entire list of ScanResults.

    Each ScanResult is rebuilt with only the unique matches; a single
    combined DeduplicationReport is returned.
    """
    all_original: List[Match] = []
    all_kept: List[Match] = []
    all_removed: List[_DedupKey] = []

    new_results: List[ScanResult] = []
    for result in results:
        kept, rep = deduplicate_matches(result.matches)
        all_original.extend(result.matches)
        all_kept.extend(kept)
        all_removed.extend(rep.removed_keys)
        new_results.append(ScanResult(file_path=result.file_path, matches=kept))

    combined = DeduplicationReport(
        original_count=len(all_original),
        deduplicated_count=len(all_kept),
        removed_keys=all_removed,
    )
    return new_results, combined
