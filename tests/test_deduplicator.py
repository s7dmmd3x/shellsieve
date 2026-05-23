"""Tests for shellsieve.deduplicator."""
from __future__ import annotations

import re
from types import SimpleNamespace
from typing import List

import pytest

from shellsieve.deduplicator import (
    DeduplicationReport,
    deduplicate_matches,
    deduplicate_results,
)
from shellsieve.scanner import Match, ScanResult
from shellsieve.patterns import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(pid: str = "SC001"):
    return SimpleNamespace(
        id=pid,
        severity=Severity.ERROR,
        message="test",
        regex=re.compile(r"eval"),
        tags=[],
    )


def _make_match(
    file_path: str = "a.sh",
    line_number: int = 1,
    pid: str = "SC001",
) -> Match:
    pat = _make_pattern(pid)
    return Match(
        file_path=file_path,
        line_number=line_number,
        line="eval foo",
        pattern=pat,
    )


# ---------------------------------------------------------------------------
# DeduplicationReport
# ---------------------------------------------------------------------------

def test_report_removed_count():
    r = DeduplicationReport(original_count=5, deduplicated_count=3)
    assert r.removed_count == 2


def test_report_as_dict_keys():
    r = DeduplicationReport(original_count=4, deduplicated_count=4)
    d = r.as_dict()
    assert "original_count" in d
    assert "deduplicated_count" in d
    assert "removed_count" in d


# ---------------------------------------------------------------------------
# deduplicate_matches
# ---------------------------------------------------------------------------

def test_deduplicate_matches_no_duplicates():
    matches = [_make_match(line_number=1), _make_match(line_number=2)]
    kept, report = deduplicate_matches(matches)
    assert len(kept) == 2
    assert report.removed_count == 0


def test_deduplicate_matches_removes_duplicate():
    m = _make_match()
    matches = [m, _make_match()]  # same key
    kept, report = deduplicate_matches(matches)
    assert len(kept) == 1
    assert report.removed_count == 1


def test_deduplicate_matches_keeps_first_occurrence():
    m1 = _make_match(line_number=1)
    m2 = _make_match(line_number=1)  # duplicate
    kept, _ = deduplicate_matches([m1, m2])
    assert kept[0] is m1


def test_deduplicate_matches_different_pattern_ids_not_duplicate():
    m1 = _make_match(pid="SC001")
    m2 = _make_match(pid="SC002")
    kept, report = deduplicate_matches([m1, m2])
    assert len(kept) == 2
    assert report.removed_count == 0


def test_deduplicate_matches_empty_list():
    kept, report = deduplicate_matches([])
    assert kept == []
    assert report.original_count == 0
    assert report.deduplicated_count == 0


# ---------------------------------------------------------------------------
# deduplicate_results
# ---------------------------------------------------------------------------

def test_deduplicate_results_combines_reports():
    r1 = ScanResult(file_path="a.sh", matches=[_make_match("a.sh", 1), _make_match("a.sh", 1)])
    r2 = ScanResult(file_path="b.sh", matches=[_make_match("b.sh", 5)])
    new_results, report = deduplicate_results([r1, r2])
    assert report.original_count == 3
    assert report.deduplicated_count == 2
    assert report.removed_count == 1


def test_deduplicate_results_preserves_file_paths():
    r1 = ScanResult(file_path="x.sh", matches=[_make_match("x.sh")])
    new_results, _ = deduplicate_results([r1])
    assert new_results[0].file_path == "x.sh"


def test_deduplicate_results_empty():
    new_results, report = deduplicate_results([])
    assert new_results == []
    assert report.original_count == 0
