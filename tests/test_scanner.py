"""Tests for shellsieve.scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult, scan_file, scan_line


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(pattern_id: str, regex: str, severity: Severity = Severity.HIGH) -> Pattern:
    import re
    return Pattern(
        id=pattern_id,
        regex=re.compile(regex),
        message="test pattern",
        severity=severity,
        description="used in tests",
    )


# ---------------------------------------------------------------------------
# scan_line
# ---------------------------------------------------------------------------

def test_scan_line_returns_match_on_hit():
    p = _make_pattern("T001", r"eval\s")
    matches = scan_line("eval $USER_INPUT\n", 1, [p])
    assert len(matches) == 1
    assert matches[0].line_number == 1
    assert matches[0].pattern is p


def test_scan_line_returns_empty_on_miss():
    p = _make_pattern("T002", r"eval\s")
    matches = scan_line("echo hello\n", 1, [p])
    assert matches == []


def test_scan_line_multiple_patterns():
    p1 = _make_pattern("T003", r"eval\s")
    p2 = _make_pattern("T004", r"rm -rf")
    matches = scan_line("eval $X; rm -rf /\n", 1, [p1, p2])
    assert len(matches) == 2


def test_match_severity_delegates_to_pattern():
    p = _make_pattern("T005", r"curl", Severity.MEDIUM)
    matches = scan_line("curl http://example.com\n", 1, [p])
    assert matches[0].severity == Severity.MEDIUM


def test_match_str_contains_line_number():
    p = _make_pattern("T006", r"eval\s")
    m = scan_line("eval $X\n", 42, [p])[0]
    assert "42" in str(m)


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------

def test_scan_file_missing_file_records_error(tmp_path):
    result = scan_file(tmp_path / "nonexistent.sh")
    assert result.errors
    assert not result.matches


def test_scan_file_clean_script(tmp_path):
    script = tmp_path / "clean.sh"
    script.write_text("#!/bin/bash\necho hello\n")
    p = _make_pattern("T007", r"eval\s")
    result = scan_file(script, patterns=[p])
    assert not result.has_issues


def test_scan_file_detects_issue(tmp_path):
    script = tmp_path / "bad.sh"
    script.write_text("#!/bin/bash\neval $USER_INPUT\n")
    p = _make_pattern("T008", r"eval\s")
    result = scan_file(script, patterns=[p])
    assert result.has_issues
    assert result.matches[0].line_number == 2


def test_scan_result_matches_by_severity(tmp_path):
    script = tmp_path / "multi.sh"
    script.write_text("eval $X\ncurl http://x.com\n")
    p_high = _make_pattern("T009", r"eval", Severity.HIGH)
    p_med = _make_pattern("T010", r"curl", Severity.MEDIUM)
    result = scan_file(script, patterns=[p_high, p_med])
    assert len(result.matches_by_severity(Severity.HIGH)) == 1
    assert len(result.matches_by_severity(Severity.MEDIUM)) == 1
    assert len(result.matches_by_severity(Severity.LOW)) == 0
