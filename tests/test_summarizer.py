"""Tests for shellsieve.summarizer."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult
from shellsieve.summarizer import ScanSummary, SeverityGroup, format_summary, summarize


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(pid: str, severity: Severity = Severity.WARNING) -> Pattern:
    return Pattern(
        id=pid,
        description="test pattern",
        regex=re.compile(r"eval"),
        severity=severity,
        tags=[],
    )


def _make_match(pid: str, severity: Severity = Severity.WARNING) -> Match:
    return Match(
        pattern=_make_pattern(pid, severity),
        line=1,
        column=0,
        source_line="eval $x",
        file=None,
    )


def _make_result(matches: List[Match]) -> ScanResult:
    return ScanResult(file=None, matches=matches)


# ---------------------------------------------------------------------------
# summarize()
# ---------------------------------------------------------------------------

def test_summarize_empty_results():
    summary = summarize([])
    assert summary.total_files == 0
    assert summary.total_matches == 0


def test_summarize_all_severity_keys_present():
    summary = summarize([])
    for sev in Severity:
        assert sev.name in summary.groups


def test_summarize_counts_matches():
    matches = [_make_match("SC001", Severity.ERROR), _make_match("SC002", Severity.WARNING)]
    summary = summarize([_make_result(matches)])
    assert summary.total_matches == 2
    assert summary.groups[Severity.ERROR.name].count == 1
    assert summary.groups[Severity.WARNING.name].count == 1


def test_summarize_total_files():
    r1 = _make_result([_make_match("SC001")])
    r2 = _make_result([_make_match("SC002")])
    summary = summarize([r1, r2])
    assert summary.total_files == 2


def test_summarize_multiple_matches_same_severity():
    matches = [_make_match(f"SC00{i}", Severity.INFO) for i in range(4)]
    summary = summarize([_make_result(matches)])
    assert summary.groups[Severity.INFO.name].count == 4


# ---------------------------------------------------------------------------
# as_dict()
# ---------------------------------------------------------------------------

def test_as_dict_keys():
    summary = summarize([])
    d = summary.as_dict()
    assert "total_files" in d
    assert "total_matches" in d
    assert "by_severity" in d


def test_as_dict_by_severity_has_all_levels():
    summary = summarize([])
    d = summary.as_dict()["by_severity"]
    for sev in Severity:
        assert sev.name in d


# ---------------------------------------------------------------------------
# format_summary()
# ---------------------------------------------------------------------------

def test_format_summary_contains_totals():
    summary = summarize([_make_result([_make_match("SC001")])])
    text = format_summary(summary, colour=False)
    assert "1" in text
    assert "Scan summary" in text


def test_format_summary_no_colour_has_no_escape_codes():
    summary = summarize([])
    text = format_summary(summary, colour=False)
    assert "\033[" not in text


def test_format_summary_colour_contains_escape_codes():
    matches = [_make_match("SC001", Severity.ERROR)]
    summary = summarize([_make_result(matches)])
    text = format_summary(summary, colour=True)
    assert "\033[" in text
