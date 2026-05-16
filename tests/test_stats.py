"""Tests for shellsieve.stats."""
import pytest
from unittest.mock import MagicMock
from collections import Counter

from shellsieve.stats import ScanStats, compute_stats, format_stats
from shellsieve.patterns import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(pattern_id: str, severity: Severity = Severity.WARNING):
    pattern = MagicMock()
    pattern.id = pattern_id
    match = MagicMock()
    match.pattern = pattern
    match.severity = severity
    return match


def _make_result(matches):
    result = MagicMock()
    result.matches = matches
    result.has_issues = bool(matches)
    return result


# ---------------------------------------------------------------------------
# ScanStats unit tests
# ---------------------------------------------------------------------------

def test_clean_files_is_difference():
    stats = ScanStats(total_files=10, files_with_issues=3)
    assert stats.clean_files == 7


def test_as_dict_contains_expected_keys():
    stats = ScanStats(total_files=2, files_with_issues=1, total_matches=4)
    d = stats.as_dict()
    assert "total_files" in d
    assert "clean_files" in d
    assert "by_severity" in d
    assert "by_pattern_id" in d


# ---------------------------------------------------------------------------
# compute_stats tests
# ---------------------------------------------------------------------------

def test_compute_stats_empty():
    stats = compute_stats([])
    assert stats.total_files == 0
    assert stats.total_matches == 0


def test_compute_stats_counts_files():
    results = [_make_result([]), _make_result([])]
    stats = compute_stats(results)
    assert stats.total_files == 2
    assert stats.files_with_issues == 0


def test_compute_stats_counts_issues():
    m = _make_match("SC001", Severity.ERROR)
    results = [_make_result([m]), _make_result([])]
    stats = compute_stats(results)
    assert stats.files_with_issues == 1
    assert stats.total_matches == 1


def test_compute_stats_by_severity():
    matches = [
        _make_match("SC001", Severity.ERROR),
        _make_match("SC002", Severity.WARNING),
        _make_match("SC003", Severity.ERROR),
    ]
    stats = compute_stats([_make_result(matches)])
    assert stats.by_severity[Severity.ERROR.value] == 2
    assert stats.by_severity[Severity.WARNING.value] == 1


def test_compute_stats_by_pattern_id():
    matches = [_make_match("SC001"), _make_match("SC001"), _make_match("SC002")]
    stats = compute_stats([_make_result(matches)])
    assert stats.by_pattern_id["SC001"] == 2
    assert stats.by_pattern_id["SC002"] == 1


# ---------------------------------------------------------------------------
# format_stats tests
# ---------------------------------------------------------------------------

def test_format_stats_contains_summary_header():
    stats = ScanStats(total_files=5, files_with_issues=2, total_matches=3)
    output = format_stats(stats)
    assert "Scan Summary" in output
    assert "5" in output


def test_format_stats_lists_pattern_ids():
    stats = ScanStats(total_files=1, files_with_issues=1, total_matches=1)
    stats.by_pattern_id["SC001"] = 1
    output = format_stats(stats)
    assert "SC001" in output


def test_format_stats_no_matches_omits_sections():
    stats = ScanStats(total_files=3)
    output = format_stats(stats)
    assert "By pattern" not in output
